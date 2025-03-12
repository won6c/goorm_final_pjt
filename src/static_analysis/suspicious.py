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
    "SetClipboardData", "GetClipboardData", "NtQuerySystemInformation", "SetErrorMode",
    "CreateFileA", "CreateFileW", "WriteFile", "ReadFile", "DeleteFileA", "DeleteFileW",
    "MoveFileA", "MoveFileW", "CopyFileA", "CopyFileW", "CreateDirectoryA", "CreateDirectoryW",
    "RemoveDirectoryA", "RemoveDirectoryW", "RegOpenKeyExA", "RegOpenKeyExW", "RegQueryValueExA",
    "RegQueryValueExW", "RegSetValueExA", "RegSetValueExW", "RegDeleteKeyA", "RegDeleteKeyW",
    "RegDeleteValueA", "RegDeleteValueW", "OpenProcess", "TerminateProcess", "CreateRemoteThread",
    "SetThreadContext", "GetThreadContext", "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    "FreeLibrary", "Send", "Recv", "NtQuerySystemInformation", "EnumProcesses", "EnumProcessModules",
    "CreateThread", "IsDebuggerPresent", "SetFileAttributesA", "SetFileAttributesW", "GetFileAttributesA",
    "GetFileAttributesW", "WSAStartup", "connect", "send", "recv", "WinHttpSendRequest",
    "CreateService", "ShellExecuteEx", "RegSetValueEx", "RegDeleteKey", "RegCreateKeyEx",
    "schtasks", "CreateRemoteThread", "RemoteDesktop", "ScreenCapture", "Keylogger", "Clipboard",
    "SystemInformation", "BrowserSteal", "GetPasswords", "Crypto", "GetAsyncKeyState"
}


packing_signatures = {
    "UPX": b"UPX!",
    "ASPack": b"ASPack",
    "MPRESS": b"MPRESS",
    "Themida": b"This program cannot be run under a virtual machine",
    "PECompact": b"PEC2",
    "EXECryptor": b"EXECryptor",
    "VMProtect": b"VMProtect",
}
