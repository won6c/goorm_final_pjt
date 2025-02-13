import wmi
import re
import pythoncom
from common import stop_event

""" proc_list() 출력값

instance of Win32_Process
{
        Caption = "chrome.exe"; <-
        CommandLine = "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=gpu-process --string-annotations=is-enterprise-managed=no --gpu-preferences=UAAAAAAAAADgAAAEAAAAAAAAAAAAAAAAAABgAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAIAAAAAAAAAAgAAAAAAAAA --use-gl=angle --use-angle=swiftshader-webgl --field-trial-handle=3344,i,12851494897505493372,5860253653722036921,262144 --variations-seed-version=20250114-180129.242000 --mojo-platform-channel-handle=2608 /prefetch:2";
        CreationClassName = "Win32_Process";
        CreationDate = "20250121031731.614073-480"; <-
        CSCreationClassName = "Win32_ComputerSystem";
        CSName = "WINDEV2407EVAL";
        Description = "chrome.exe";
        ExecutablePath = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"; <-
        Handle = "6640";
        HandleCount = 314;
        KernelModeTime = "781250";
        MaximumWorkingSetSize = 1380;
        MinimumWorkingSetSize = 200;
        Name = "chrome.exe";
        OSCreationClassName = "Win32_OperatingSystem";
        OSName = "Microsoft Windows 11 Enterprise Evaluation|C:\\Windows|\\Device\\Harddisk0\\Partition4";
        OtherOperationCount = "607";
        OtherTransferCount = "33228";
        PageFaults = 12403;
        PageFileUsage = 15760;
        ParentProcessId = 5936;
        PeakPageFileUsage = 15760;
        PeakVirtualSize = "2306973573120";
        PeakWorkingSetSize = 45620;
        Priority = 10;
        PrivatePageCount = "16138240";
        ProcessId = 6640; <-
        QuotaNonPagedPoolUsage = 21;
        QuotaPagedPoolUsage = 795;
        QuotaPeakNonPagedPoolUsage = 110;
        QuotaPeakPagedPoolUsage = 796;
        ReadOperationCount = "63";
        ReadTransferCount = "27192";
        SessionId = 1;
        ThreadCount = 16;
        UserModeTime = "312500";
        VirtualSize = "2306973573120";
        WindowsVersion = "10.0.22621";
        WorkingSetSize = "46714880";
        WriteOperationCount = "45";
        WriteTransferCount = "103048";
};

"""

def extract_process_info(new_process):
    data = str(new_process)
    # 추출할 필드명
    fields = [
        "Caption", "CommandLine", "CreationDate", "CSName", "Description", 
        "ExecutablePath", "HandleCount", "KernelModeTime", "MaximumWorkingSetSize", 
        "MinimumWorkingSetSize", "Name", "OtherOperationCount", "OtherTransferCount", 
        "ParentProcessId", "Priority", "ProcessId", "ReadOperationCount", 
        "ReadTransferCount", "ThreadCount", "VirtualSize", "WriteOperationCount", 
        "WriteTransferCount"
    ]

    # 딕셔너리로 저장
    process_info = {}
    name = ""
    # 데이터 파싱 및 추출
    for field in fields:
        pattern = re.compile(rf'{field} = "(.*?)";' if field != "ProcessId" else rf'{field} = (\d+);')
        match = pattern.search(data)
        if match:
            process_info[field] = match.group(1)
            if field=="Caption":
                name = process_info[field]

    return name, process_info

def process_list():
    pythoncom.CoInitialize()
    proc = wmi.WMI()
    process_watcher = proc.Win32_process.watch_for("creation")
    process_result = {}
    while not stop_event.is_set():
        try:
            new_process = process_watcher()
            if stop_event.is_set():
                break
            print(f"프로세스 생성됨: {new_process.Caption} (PID: {new_process.ProcessId})")
            name, process_info = extract_process_info(new_process)
            if "frida" in name:
                pass
            else:
                process_result[name]=process_info
        except Exception as e:
            print(f"오류 발생: {e}")
            break
    pythoncom.CoUninitialize()
    return process_result
