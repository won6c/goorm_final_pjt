suspicious_apis = {
        "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory", "GetProcAddress",
    "LoadLibraryA", "LoadLibraryW", "TerminateProcess", "ShellExecuteA", "ShellExecuteW",
    "WinExec", "SetThreadContext", "GetThreadContext", "CreateProcessA", "CreateProcessW",
    "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW", "HttpOpenRequestA",
    "HttpOpenRequestW", "URLDownloadToFileA", "URLDownloadToFileW", "CryptEncrypt", "CryptDecrypt",
    "OpenProcess", "CloseHandle", "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "SetWindowsHookExA",
    "SetWindowsHookExW", "UnhookWindowsHookEx", "RegCreateKeyExA", "RegCreateKeyExW", "RegSetValueExA",
    "RegSetValueExW", "RegDeleteKeyA", "RegDeleteKeyW", "RegDeleteValueA", "RegDeleteValueW",
    "EnumProcesses", "EnumProcessModules", "FindWindowA", "FindWindowW", "OpenClipboard",
    "SetClipboardData", "GetClipboardData", "NtQuerySystemInformation"
}
