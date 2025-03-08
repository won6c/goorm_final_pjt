import os
import sys

TOOLS = {
    "EXIFTOOL_PATH":"exiftool\\exiftool.exe",
    "STRINGS_PATH":"strings\\strings.exe",
    "PROCDUMP_PATH":"procdump\\procdump.exe",
}

Results = {
    "MID_RESULT_PATH":"mid_result.json",
    "FINAL_RESULT_PATH":"final_result.json",
    "PCAP_OUTPUT_PATH":"captured_packets.pcap",
    "REG_CHANGE_OUTPUT_PATH":"reg_changes.json",
    "IDENTIFY_OUTPUT_PATH":"identify.json"
}

WATCH_DIRS = [
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/AppData/Local"),
    os.path.expanduser("~/Documents")
]

IGNORED_EXTENSIONS = {".tmp", ".lnk", ".log", ".index", ".ft", ".intermediate.txt"}

BASE_PATH = os.getcwd()

OUTPUT_PATH = os.path.join(BASE_PATH, "OUTPUT")
TOOLS_PATH = os.path.join(BASE_PATH, "Tools")
RULE_FOLDER_PATH = os.path.join(BASE_PATH, "YARA_RULE")

LOG_THROTTLE_TIME = 5
THRESHOLD = 10
TIMEOUT = 60

SCAN_FOLDER = r"C:\Users\User\Desktop\DestDir"

JS_SCRIPT_PATH = os.path.join(os.getcwd(), "dynamic_analysis", "frida_py", "frida_stalker.js")

MID_RESULT_PATH = os.path.join( OUTPUT_PATH, Results["MID_RESULT_PATH"])
PCAP_OUTPUT_PATH = os.path.join( OUTPUT_PATH, Results["PCAP_OUTPUT_PATH"])
REG_CHANGE_OUTPUT_PATH = os.path.join( OUTPUT_PATH, Results["REG_CHANGE_OUTPUT_PATH"])
IDENTIFY_OUTPUT_PATH = os.path.join( OUTPUT_PATH, Results["IDENTIFY_OUTPUT_PATH"])
FINAL_RESULT_OUTPUT_PATH = os.path.join( OUTPUT_PATH, Results["FINAL_RESULT_PATH"])

EXIFTOOL_PATH = os.path.join(TOOLS_PATH,TOOLS["EXIFTOOL_PATH"])
STRINGS_PATH = os.path.join(TOOLS_PATH,TOOLS["STRINGS_PATH"])
PROCDUMP_PATH = os.path.join(TOOLS_PATH,TOOLS["PROCDUMP_PATH"])

AWS_IP = ""
ELASTICSEARCH_URL = f'http://{AWS_IP}:9200'
KIBANA_URL = f'http://{AWS_IP}:5601'
INDEX_NAME = f'{os.path.basename(sys.argv[1])}-*'

DUMP_FILE = "memory.dmp"

SIGNATURES = {
    'Ransomware': {
        'CryptHashData', 'CryptStringToBinary ', 'CryptDecrypt', 'CryptDestroyHash', 'CryptAcquireContext', 'CryptSetKeyParam', 'GetLogicalDrives', 
        'FlushEfsCache', 'FindNextFile', 'CryptGenKey', 'DecryptFileA', 'EnumSystemLocalesA', 'CryptDeriveKey', 'CryptGenRandom', 'GetDriveTypeA', 
        'CryptAcquireContextA', 'CryptGetHashParam ', 'CryptCreateHash', 'EncryptFileA', 'CryptDestroyKey', 'FindFirstFile', 'CryptEncrypt', 
        'CryptReleaseContext', 'CryptBinaryToString', 'CryptProtectData'
    }, 
    'Loader': {
        'InternetOpen', 'WriteProcessMemory', 'GetProcAddress', 'CreateRemoteThread', 'LoadLibrary', 'VirtualAllocEx', 'InternetConnect', 
        'HttpSendRequest', 'CreateProcess', 'HttpOpenRequest'
    }, 
    'Infostealer': {
        'FindNextFile', 'CryptUnprotectData', 'InternetOpen', 'ReadFile', 'FindFirstFile', 'RegQueryValueEx', 'InternetConnect', 
        'RegOpenKeyEx', 'HttpSendRequest', 'HttpOpenRequest'
    }, 
    'RAT': {
        'connect', 'recv', 'WSASocket', 'OpenProcess', 'WriteProcessMemory', 'GetAsyncKeyState', 'ShellExecuteEx', 'CreateRemoteThread', 
        'SetWindowsHookEx', 'VirtualAllocEx', 'socket', 'CreateProcess', 'send', 'WSAStartup'
    }, 
    'Enumeration': {
        'FindFirstFileA', 'GetSystemTimeAsFileTime', 'WNetEnumResourceA', 'GetCurrentProcess', 'Thread32Next', 'RegEnumValueA', 'EnumDesktopWindows', 
        'VirtualQueryEx', 'GetVersionExA', 'EnumWindows', 'GetProcessIdOfThread', 'Module32Next', 'NetShareGetInfo', 'GetSystemDefaultLangId', 
        'GetCurrentThread', 'GetCurrentProcessId', 'RegEnumKeyExA', 'PathFileExistsA', 'RtlGetVersion', 'GetSystemDirectoryA', 'GetIpNetTable', 
        'FindFirstUrlCacheEntryA', 'GetLogicalProcessorInformationEx', 'GetThreadLocale', 'GetLogicalDrives', 'GetCurrentHwProfileA', 'NetShareEnum', 
        'GetFileTime ', 'Process32Next', 'SearchPathA', 'GetSystemTime', 'NtQuerySystemEnvironmentValueEx', 'GetThreadInformation', 'GetAdaptersInfo', 
        'Process32First', 'RegQueryMultipleValuesA', 'ReadFile', 'GetComputerNameA', 'EnumProcesses', 'GetLogicalProcessorInformation', 
        'GetFileAttributesA ', 'WNetAddConnection2A', 'WNetAddConnectionA', 'LookupAccountNameA', 'GetProcessId', 'GetCurrentThreadId', 
        'EnumSystemLocalesA', 'Module32First', 'FindNextUrlCacheEntryA', 'EnumProcessModulesEx', 'IsWoW64Process', 'GetDriveTypeA', 'ReadProcessMemory', 
        'GetUserNameA', 'RegQueryValueExA', 'GetNativeSystemInfo', 'GetWindowsDirectoryA', 'FindNextFileA', 'EnumResourceTypesExA', 'EnumDeviceDrivers', 
        'EnumProcessModules', 'CreateToolhelp32Snapshot', 'EnumResourceTypesA', 'GetThreadId', 'RegQueryInfoKeyA', 'GetModuleBaseNameA', 
        'LookupPrivilegeValueA', 'Thread32First', 'NetShareCheck', 'RegEnumKeyA', 'WNetCloseEnum', 'NtQueryDirectoryFile', 'NtQueryInformationProcess'
    }, 
    'Injection': {
        'CreateFileMappingA', 'NtWaitForMultipleObjects', 'AdjustTokenPrivileges', 'NtQueueApcThread', 'VirtualProtectFromApp', 
        'NtReadVirtualMemory', 'WriteProcessMemory', 'NtCreateSection', 'NtQueueApcThreadEx2', 'Process32Next', 'VirtualAllocFromApp', 
        'NtCreateThreadEx', 'CreateRemoteThread', 'MapViewOfFileEx', 'ReadProcessMemory', 'NtReadVirtualMemoryEx', 'NtQueueApcThreadEx', 
        'NtCreateProcess', 'DebugActiveProcessStop', 'Toolhelp32ReadProcessMemory', 'GlobalAlloc', 'LdrLoadDll', 'HeapReAlloc', 'NtResumeProcess', 
        'SetThreadContext', 'LoadLibraryA', 'SetPropA', 'SuspendThread', 'Wow64SetThreadContext', 'RtlMoveMemory ', 'VirtualProtectEx', 
        'GetThreadContext', 'WaitForMultipleObjects', 'NtOpenProcess', 'NtContinue', 'GetProcessHeap', 'CreateProcessInternal', 'Thread32Next', 
        'NtUnmapViewOfSection', 'MapViewOfFile', 'LoadLibraryExA', 'NtOpenThread', 'OpenProcess', 'NtCreateThread', 'NtWriteVirtualMemory', 
        'RtlCopyMemory', 'VirtualAllocEx', 'WaitForSingleObjectEx', 'VirtualAlloc2', 'NtWaitForSingleObject', 'GetModuleHandleA', 'VirtualAlloc', 
        'WaitForSingleObject ', 'Process32First', 'GetProcAddress', 'VirtualAllocExNuma', 'HeapAlloc', 'NtResumeThread', 'QueueUserAPC', 
        'MapViewOfFile2', 'NtAdjustPrivilegesToken', 'LocalAlloc', 'OpenFileMappingA', 'CreateProcessAsUserA', 'DuplicateToken', 'CreateRemoteThreadEx', 
        'VirtualAlloc2FromApp', 'SetProcessDEPPolicy', 'NtSuspendProcess', 'MapViewOfFile3', 'OpenProcessToken', 'CreateThread', 'HeapCreate', 
        'RtlCreateHeap', 'WaitForMultipleObjectsEx', 'GetProcessHeaps', 'NtAllocateVirtualMemory', 'NtMapViewOfSection', 'NtDuplicateObject', 
        'KeInsertQueueApc', 'EnumSystemLocalesA', 'VirtualProtect', 'CreateProcessWithTokenW', 'NtProtectVirtualMemory', 'OpenThread', 'CreateProcessA', 
        'Thread32First', 'NtCreateProcessEx', 'NtCreateUserProcess', 'UuidFromStringA', 'ResumeThread'
    }, 
    'Evasion': {
        'IcmpSendEcho', 'SizeOfResource', 'DeleteFileA', 'CreateFileMappingA', 'CreateProcessInternal', 'NtWaitForMultipleObjects', 
        'SetTimer', 'LoadLibraryExA', 'WaitForMultipleObjectsEx', 'LoadResource', 'SetEnvironmentVariableA', 'Sleep', 'ImpersonateLoggedOnUser', 
        'TimeGetTime', 'WaitForSingleObjectEx', 'CreateWindowExA', 'NtWaitForSingleObject', 'SetFileAttributesA ', 'GetModuleHandleA', 
        'WaitForSingleObject ', 'LoadLibraryA', 'SleepEx ', 'GetProcAddress', 'LockResource', 'SetWaitableTimer', 'Select', 'EnumSystemLocalesA', 
        'NtDelayExecution', 'RegisterHotKey', 'SetFileTime', 'CreateWaitableTimer', 'SetThreadToken', 'timeSetEvent', 'DuplicateToken', 
        'WaitForMultipleObjects', 'CreateTimerQueueTimer', 'UuidFromStringA', 'CryptProtectData'
    }, 
    'Spying': {
        'SetWindowsHookExA', 'GetWindowDC', 'UnhookWindowsHookEx', 'MapVirtualKeyA', 'GetKeynameTextA', 'GetDC', 'StretchBlt', 
        'GetRawInputData', 'PeekMessageA', 'GetDCEx', 'GetMessageA', 'RegisterRawInputDevices', 'GetClipboardData', 'SetWinEventHook', 
        'MapVirtualKeyExA', 'BitBlt', 'GetAsyncKeyState', 'SendMessageA', 'GetKeyboardState', 'AttachThreadInput', 'RegisterHotKey', 'GetKeyState', 
        'PostMessageA', 'CallNextHookEx', 'SendMessageTimeoutA', 'GetForegroundWindow', 'SendMessageCallbackA', 'SendNotifyMessageA', 'PostThreadMessageA'
    }, 
    'Internet': {
        'InternetReadFile', 'HttpOpenRequestA', 'WSACleanup', 'URLOpenStream', 'URLOpenBlockingStream', 'InternetOpenA', 'Recv', 'URLDownloadToCacheFile',
        'FindFirstUrlCacheEntryA', 'InternetCloseHandle', 'Socket', 'URLDownloadToFile', 'Listen', 'ShellExecuteA', 'WSAStartup', 'Send', 'Connect', 
        'Gethostname', 'Inet_addr', 'WSASocketA', 'Accept', 'DnsQuery_A', 'Closesocket', 'HttpSendRequestExA', 'HttpSendRequestA', 'WinExec', 
        'WNetOpenEnumA', 'InternetSetOptionA', 'FindNextUrlCacheEntryA', 'ShellExecuteExA', 'HttpAddRequestHeaders', 'InternetOpenUrlA', 'FtpPutFileA', 
        'ioctlsocket', 'Bind', 'WSAIoctl', 'InternetConnectA', 'Gethostbyname', 'InternetReadFileExA', 'DnsQueryEx', 'InternetWriteFile'
    }, 
    'Anti-Debugging': {
        'IsDebuggerPresent', 'GetSystemTimeAsFileTime', 'GetTickCount', 'QueryPerformanceFrequency', 'Sleep', 'RtlGetVersion', 
        'GetLogicalProcessorInformationEx', 'OutputDebugStringA', 'GetSystemTime', 'SleepEx ', 'QueryPerformanceCounter', 'GetComputerNameA', 
        'GetLogicalProcessorInformation', 'CountClipboardFormats', 'ExitWindowsEx', 'GetTickCount64', 'FindWindowExA', 'GetUserNameA', 
        'GetNativeSystemInfo', 'FindWindowA', 'CreateToolhelp32Snapshot', 'GetForegroundWindow', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess'
    }, 
    'Helper': {
        'lstrcatA', 'RegCloseKey', 'RegLoadMUIStringA', 'SetWindowLongA', 'ControlService', 'GetLogicalDrives', 'StartServiceA', 'MoveFileExA', 
        'TerminateThread', 'CreateMutexA', 'RegDeleteKeyTransactedA', 'LockResource', 'CopyFile2', 'CreateFile2', 'RegDeleteKeyExA', 'IsWoW64Process', 
        'PeekNamedPipe', 'TerminateProcess ', 'FindResourceA', 'RegFlushKey', 'CreateServiceA', 'RegEnumKeyA', 'RegRestoreKeyA', 'SizeOfResource', 
        'NtSetInformationProcess', 'NtCreateFile', 'NtShutdownSystem', 'RegCopyTreeA', 'OpenServiceA', 'CreateFileA', 'NtClose', 'RegEnumKeyExA', 
        'GetTempFileNameA', 'DeleteService', 'NtResumeProcess', 'RegSetKeyValueA', 'GetModuleFileNameA', 'RegOpenKeyA', 'RegLoadKeyA', 'SetFocus', 
        'ControlServiceExA', 'CreatePipe', 'NtSetInformationThread', 'RegOpenCurrentUser', 'ShowWindow', 'RegOverridePredefKey', 'CallWindowProcA', 
        'NtSetValueKey', 'ConnectNamedPipe', 'RegDeleteKeyA', 'WNetEnumResourceA', 'NtDeleteValueKey', 'RegDeleteValueA ', 'FindResourceExA', 
        'RegOpenKeyTransactedA', 'RegConnectRegistryA', 'RegGetKeySecurity', 'RegDeleteValueA', 'FindClose', 'NtMakeTemporaryObject', 'RegUnLoadKeyA', 
        'GetDesktopWindow', 'NetShareAdd', 'NtSetSystemEnvironmentValueEx', 'UnmapViewOfFile', 'NetShareSetInfo ', 'RegOpenKeyExA', 'WNetAddConnection2A', 
        'NtTerminateProcess', 'RegCreateKeyA', 'RegCreateKeyTransactedA', 'SetForegroundWindow', 'RegSetKeySecurity', 'RegCreateKeyExA', 'RegGetValueA', 
        'CopyFileExA', 'SetThreadToken', 'RegSaveKeyA', 'SetCurrentDirectory', 'RegEnumValueA', 'StartServiceCtrlDispatcherA', 'OpenClipboard', 
        'CopyFileA', 'UuidFromStringA', 'NtSetContextThread', 'NtTerminateThread', 'GetIpNetTable', 'ImpersonateLoggedOnUser', 'OpenSCManagerA', 
        'DrawTextExA', 'RegDeleteTreeA', 'RegReplaceKeyA', 'BringWindowToTop', 'MoveFileA', 'SetWindowLongPtrA', 'NtDeleteKey', 'GetModuleFileNameExA', 
        'RtlSetProcessIsCritical', 'CreateMutexExA', 'RegDeleteKeyValueA', 'WNetOpenEnumA', 'NtQueryTimer', 'GetDriveTypeA', 'GetTempPathA', 
        'DeviceIoControl', 'RegSetValueExA', 'GetModuleBaseNameA', 'RegOpenUserClassesRoot', 'SetThreadPriority', 'SetClipboardData', 'RegSaveKeyExA', 
        'WriteFile'
    }
}