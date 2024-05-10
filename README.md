# Backdoor Trojan with Process Injection and DLL Injection

This repository contains code for creating a backdoor Trojan with process injection and DLL injection techniques. This malware, created by "Sicko," demonstrates how malicious actors can exploit vulnerabilities in Windows operating systems to inject and execute malicious code covertly.

## Features

- **Process Injection**: The malware injects a dynamic link library (DLL) into a target process, allowing it to execute code within the context of the process.
- **DLL Injection**: The malware injects a payload DLL into a target process, enabling it to perform various malicious activities, including privilege escalation and executing PowerShell scripts.
- **Privilege Escalation**: The malware attempts to escalate privileges using various methods, such as bypassing User Account Control (UAC) and creating a malicious service.
- **Dynamic Payload Retrieval**: The malware retrieves payload DLL and PowerShell script from a remote server dynamically.
- **Integrity Verification**: The malware verifies the integrity of the payload DLL using SHA256 checksum validation before execution.
- **Error Logging**: The malware logs errors for debugging and monitoring purposes.

## MITRE ATT&CK Techniques

This malware employs several techniques outlined in the MITRE ATT&CK framework:

- **T1055 Process Injection**: Process injection is used to inject malicious code into a legitimate process, allowing it to execute stealthily within the context of the target process.
- **T1055.003 Dynamic-link Library Injection**: The malware utilizes DLL injection to load a payload DLL into a target process, enabling it to execute malicious code.
- **T1078 Valid Accounts**: The malware may abuse valid user accounts to escalate privileges or perform other malicious activities on the victim's system.
- **T1106 Execution through API**: The malware executes malicious activities through API calls, such as injecting DLLs into processes or creating remote threads.
- **T1107 File Deletion**: The malware may delete files or traces of its presence to evade detection and cover its tracks.

## Impact on Victim Computer

The impact of this backdoor Trojan on the victim's computer can be severe:

- **Data Theft**: The malware may steal sensitive information such as credentials, financial data, or personal information from the victim's system.
- **Unauthorized Access**: Once installed, the malware can provide attackers with remote access to the victim's computer, allowing them to execute commands, install additional malware, or perform other malicious activities.
- **Privilege Escalation**: The malware attempts to escalate privileges on the victim's system, potentially granting attackers elevated access and control over critical system resources.
- **System Compromise**: The presence of this malware can compromise the security and integrity of the victim's system, leading to further exploitation, data loss, or system instability.

## Usage

To use this malware, follow these steps:

1. **Compile the C code** for both the injector and payload DLL.
2. **Run the injector executable** with the target process name and DLL path as arguments.
   - Alternatively, run the injector executable with the process ID and DLL path as arguments.
3. The injector will inject the payload DLL into the target process and execute malicious activities.
4. Additional malicious activities can be added to the payload DLL as needed.

## Disclaimer

**Warning**: This repository is for educational purposes only. Unauthorized use of this code for malicious purposes is illegal and unethical. The author and contributors are not responsible for any damages caused by the misuse of this code.
