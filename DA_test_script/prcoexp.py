import sys
import os
import signal
import subprocess
import json

def listdll_exe():
    tool_path = os.path.join(os.getcwd(), "..", "SysinternalsSuite\\")
    tool = "Listdlls.exe"
    proc_dll_dict = {}
    try: 
        process = subprocess.Popen([f"{tool_path}{tool}","-accepteula","chrome.exe"],stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        stdout, stderr = process.communicate()
        output = stdout.decode()
        error =stderr.decode()
        pid = None
        cmd = None
        proc = None
        dll_list = []
        pid_division = 0
        count = 0
        for line in output.splitlines():
            if count<5:
                count+=1
                continue
            if pid_division==0 and line=="------------------------------------------------------------------------------":
                if pid==None:
                    pass
                else:
                    del dll_list[0]
                    proc_dll_dict.update({pid:{"proc":proc,"cmd":cmd,"dll_list":dll_list}})
                pid_division=1
                pid = None
                cmd = None
                proc = None
                dll_list = []
                continue
            else:
                pid_division=0
                if pid==None:
                    tmp = line.split()
                    proc = tmp[0]
                    pid = tmp[2]
                    print(f"pid = {pid}")
                    print(f"proc = {proc}")
                elif cmd==None:
                    tmp = line.split()
                    cmd = tmp[2]+" "+tmp[3]
                    cmd = cmd.replace("\"","")
                    print(f"cmd = {cmd}")
                elif line=="":
                    continue
                else:
                    tmp = line.split(maxsplit=2)[2]
                    idx = tmp.rfind("\\")
                    dll_list.append(tmp[idx+1:])
        del dll_list[0]
        proc_dll_dict.update({pid:{"proc":proc,"cmd":cmd,"dll_list":dll_list}})
        dll_json = json.dumps(proc_dll_dict,indent=4)
        print(dll_json)
        process.wait() 
    except KeyboardInterrupt: 
        process.send_signal(signal.SIGINT) 
        process.terminate() 
        process.wait() 
        exit(1)

def handle_exe():
    tool_path = os.path.join(os.getcwd(), "..", "SysinternalsSuite\\")
    tool = "handle64.exe"
    proc_dll_dict = {}
    try: 
        process = subprocess.Popen([f"{tool_path}{tool}","-accepteula","-a"],stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        stdout, stderr = process.communicate()
        output = stdout.decode()
        error =stderr.decode()
        print(output)
        process.wait() 
    except KeyboardInterrupt:
        process.send_signal(signal.SIGINT) 
        process.terminate() 
        process.wait() 
        exit(1)


def main():
    listdll_exe()
    handle_exe()

if __name__=="__main__":
    main()