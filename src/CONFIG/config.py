import os

TOOLS = {
    "EXIFTOOL_PATH":"exiftool\\exiftool.exe",
    "STRINGS_PATH":"strings\\strings.exe",
}

Results = {
    "MID_RESULT_PATH":"mid_result.json",
    "FINAL_RESULT_PATH":"final_result.json",
    "PCAP_OUTPUT_PATH":"captured_packets.pcap",
    "REG_CHANGE_OUTPUT_PATH":"reg_changes.json",
    "IDENTIFY_OUTPUT_PATH":"identify.json"
}

SIGNATURES = {
    "Ransomware": {
        "CryptAcquireContext", "CryptGenKey", "CryptEncrypt", "CryptDecrypt",
        "FindFirstFile", "FindNextFile"
    },
    "Loader": {
        "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest",
        "CreateProcess", "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
        "LoadLibrary", "GetProcAddress"
    },
    "Infostealer": {
        "RegOpenKeyEx", "RegQueryValueEx", "CryptUnprotectData", "ReadFile",
        "FindFirstFile", "FindNextFile", "InternetOpen", "InternetConnect",
        "HttpOpenRequest", "HttpSendRequest"
    },
    "RAT": {
        "WSAStartup", "WSASocket", "socket", "connect", "send", "recv",
        "CreateProcess", "OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
        "CreateRemoteThread", "SetWindowsHookEx", "GetAsyncKeyState", "ShellExecuteEx"
    }
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