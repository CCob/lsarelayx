#ifndef LSARELAYX_HXX
#define LSARELAYX_HXX

#define WIN32_NO_STATUS
#define SECURITY_WIN32
#define UNICODE

#include <windows.h>
#include <sspi.h>
#include <ntsecapi.h>
#include <ntsecpkg.h>
#include <map>

#include <stdio.h>
#include <strsafe.h>
#include <cstdint>
#include <winternl.h>
#include <sspi.h>
#include "pipe.hxx"

#include "commands.h"
#include "relaycontext.h"

typedef struct _LSA_PACKAGE_NAME{
    ULONG_PTR      PackageID;          // Assigned package ID
    DWORD          PackageIndex;       // Package Index in DLL
    DWORD          fPackage;
    UNICODE_STRING PackageName;
}LSA_PACKAGE_NAME, *PLSA_PACKAGE_NAME;


typedef struct _LSA_PACKAGE_INFO{
    uint64_t version;
    uint64_t reserved;
    PLSA_PACKAGE_NAME packageName;
} LSA_PACKAGE_INFO, *PLSA_PACKAGE_INFO;

typedef struct _LSAP_SECURITY_PACKAGE {
    ULONG_PTR       dwPackageID;        // Assigned package ID
    DWORD           PackageIndex;       // Package Index in DLL
    DWORD           fPackage;           // Flags about the package
    DWORD           fCapabilities;      // Capabilities that the package reported
    DWORD           dwRPCID;            // RPC ID
    DWORD           Version;
    DWORD           TokenSize;
    DWORD           ContextHandles ;    // Number of outstanding contexts
    DWORD           CredentialHandles ; //  ditto for credentials
    LONG            CallsInProgress ;   // Number of calls to this package
    SECURITY_STRING Name;               // Name of the package
    SECURITY_STRING Comment;
    struct _DLL_BINDING *   pBinding;   // Binding of DLL
    PSECPKG_EXTENDED_INFORMATION Thunks ;   // Thunked Context levels
    LIST_ENTRY      ScavengerList ;
    SECURITY_STRING WowClientDll ;
    LONGLONG        Unknown;
    SECPKG_FUNCTION_TABLE FunctionTable;    // Dispatch table

#ifdef TRACK_MEM
    PVOID           pvMemStats;         // Memory statistics
#endif

} LSAP_SECURITY_PACKAGE, *PLSAP_SECURITY_PACKAGE;

typedef _LSAP_SECURITY_PACKAGE* (*SpmpLookupPackagefn)(PUNICODE_STRING packageName);
typedef std::map<LSA_SEC_HANDLE, RelayContext*> RelayContextMap;

extern MessageExchangeFactoryPtr g_messageExchangeFactory;
extern PLSA_SECPKG_FUNCTION_TABLE g_FunctionTable;

extern SpAcceptLsaModeContextFn* msv1_0_SpAcceptLsaModeContext_orig;
extern SpDeleteContextFn* msv1_0_SpDeleteSecurityContext_orig;
extern SpAcceptLsaModeContextFn* Nego_SpAcceptLsaModeContext_orig;
extern SpDeleteContextFn* Nego_SpDeleteSecurityContext_orig;

extern RelayContextMap g_RelayContexts;
extern SpmpLookupPackagefn SpmpLookupPackage;

extern "C" NTSYSAPI NTSTATUS NtAllocateLocallyUniqueId(PLUID Luid);

int GetTokenBufferInfo(PSecBufferDesc secBufferDesc, int32_t& index);
MessageBuffer GetTokenMessageBuffer(PSecBufferDesc secBuffer, int32_t& index);

#endif // LSARELAYX_HXX
