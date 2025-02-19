import subprocess
import psutil
import win32api
import win32process
import os
import pprint
from common import stop_event

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
        while not stop_event.is_set():
            dlls.extend(trace_dll_calling(pid))
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        print(f"Process {pid} terminated or access denied")
    dlls = list(set(dlls))
    #dlls.remove("Error")
    return dlls

def process_dll(pid):
    dlls = monitor_process(pid)
    return dlls

