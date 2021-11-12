# lsarelayx

## Introduction

lsarelayx is system wide NTLM relay tool designed to relay any incoming NTLM based authentication to the host it is running on.  lsarelayx will relay **any** incoming authentication request which includes SMB.  Since lsarelayx  hooks into existing application authentication flows, the tool will also attempt to service the original authentication request after the relay is complete.  This will prevent the target application/protocol from displaying errors and function as normal for end users authenticating against the lsarelayx host.

### **Features**

* Relays NTLM connections system wide, including SMB, HTTP/HTTPS, LDAP/LDAPS or any other thrid party application implemnting the Windows authentication APIs.
* Where possible, downgrades incoming Kerberos authentication requests to NTLM.  This will cause clients that would traditionally attempt Kerberos authentication to fallback to NTLM.
* Performs an LDAP query for the relayed user to fetch group membership info an create the correct authentication token for the original request.
* Dumps NetNTLM messages for offline cracking.
* Supports a passive mode that does not relay and only dumps captured NetNTLM hashes.

## How it works

lsarelayx comes in three parts.  A fake LSA authentication provider (AP) implemented within liblsarelay.dll, a user mode console application as the control interface and a new ntlmrelayx server module called RAW.

### liblsarelayx.dll

liblsarelayx.dll is the LSA authentication provider that gets loaded by lsarelayx.  It's predominant purpose is to hook the NTLM and Negotiate packages to facilitating redirecting authetication requests to lsarelayx over a local named pipe for relaying and dumping NetNTLM hashes.  liblsarelayx is designed to be a simple as possible where all the heavy lifting is performed by lsarelayx

### lsarelayx.exe

lsarelayx.exe is the main console application used to load the custom LSA authentication provider (liblsarelayx.dll), listen for incoming NTLM and Negotiate tokens from the authentication provider and relay to ntlmrelayx's RAW server module.  The tool also performs the LDAP queries used for capturing group information for relayed users and passing back to the LSA authentication provider.

### RAW ntlmrelayx module

impacket's ntlmrelayx has implemented a siginficant amount of work creating relay attacks and will continue to improve and add further attack in the future.  To take advantage of this in favour of reimplemneting attacks directly within lsarelayx, a new ntlmrelayx server module was created called RAW.  Currently there is a [PR open on GitHub](https://github.com/SecureAuthCorp/impacket/pull/1190) that implements the RAW server module.  The RAW server module is protocol agnostic and is designed to accept the raw NTLM messages directly from 3rd party software like lsarelayx.

## Usage

### Active Mode

lsarelayx requires local administrator permissions to run.  To run in active relay mode, the host address where ntlmrelayx is running the raw server module needs to be specified.  The default port is 6666.  This can be overriden with the `--port` argument, but be sure to have also overidden the port on the ntlmrelayx side too.

```
lsarelayx.exe --host 192.168.1.1
```

### Passive Mode

You can also run lsarelayx in passive mode by running without any arguments

```
lsarelayx.exe
```

## WARNING!

liblsarelayx.dll will be loaded inside the critical lsass.exe process.  If liblsarelayx.dll has any bugs that lead to crashing lsass.exe, the host **WILL** reboot after 60s.  Whilst best efforts have been made to write bug free code, I can't promise anything.  Don't come crying to me that you took your FTSE/NASDAQ 50 company down for crashing the busy file server after using lsarelayx.

