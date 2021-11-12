
NTSTATUS msv1_0_SpDeleteSecurityContextHook(LSA_SEC_HANDLE ContextHandle);

NTSTATUS msv1_0_SpAcceptLsaModeContextHook(LSA_SEC_HANDLE CredentialHandle, LSA_SEC_HANDLE ContextHandle, PSecBufferDesc InputBuffer, ULONG ContextRequirements, ULONG TargetDataRep, PLSA_SEC_HANDLE NewContextHandle,
                                    PSecBufferDesc OutputBuffer, PULONG ContextAttributes, PTimeStamp ExpirationTime, PBOOLEAN MappedContext, PSecBuffer ContextData);
