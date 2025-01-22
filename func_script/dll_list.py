import subprocess
import psutil
import win32api
import win32process
import os

def execute_malware(file_path):
    proc = subprocess.Popen(file_path,creationflags=subprocess.CREATE_NEW_CONSOLE)
    return proc.pid


def trace_dll_calling(pid):
    try:
        process_handle =win32api.OpenProcess(0x0400|0x0010,False,pid)
        modules = win32process.EnumProcessModules(process_handle)
        dlls = [win32process.GetModuleFileNameEx(process_handle,mod) for mod in modules]
        return dlls
    except Exception as e:
        return [f"Error"]

def monitor_process(pid):
    dlls = []
    try:
        proc = psutil.Process(pid)
        while proc.is_running():
            print(f"Running process name : {proc.name}, pid : {proc.pid}")
            dlls.extend(trace_dll_calling(pid))
            print(f"Loaded DLLs : {dlls}")
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        print(f"Process {pid} terminated or access denied")
    dlls = list(set(dlls))
    dlls.remove("Error")
    return dlls

def main():
    file_path = "C:\\\Program Files\\Bandizip\\Bandizip.exe"
    pid = execute_malware(file_path=file_path)
    dlls = monitor_process(pid)
    print()
    print()
    print(dlls)

if __name__=="__main__":
    main()