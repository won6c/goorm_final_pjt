import os
import subprocess
import signal
import json
import time
import Evtx.Evtx as evtx
import Evtx.Views as e_views
from bs4 import BeautifulSoup

def noriben():
    tool_path = os.path.join(os.getcwd(), "..", "SysinternalsSuite\\")
    log_path = os.path.join(os.getcwd(),"noriben_tmp\\")
    tool = "Noriben.py"
    output_txt = ""
    try:
        process = subprocess.Popen(["py",f"{tool_path}{tool}", "--output", f"{log_path}"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        time.sleep(40)
        print('')
        process.send_signal(signal.CTRL_C_EVENT)
        process.wait() 
        #process.terminate()
    except KeyboardInterrupt:
        process.terminate()
    except Exception as e:
        print(e)
    finally:
        noriben_output = os.walk(log_path)
        for dirpath, dirnames, filenames in noriben_output:
            output_txt = [file for file in filenames if file.endswith(".txt")][0]
    content = ""
    with open(log_path+output_txt,"r") as f:
        content = f.read()
    procname = "svchost.exe"
    for line in content.splitlines():
        if f"{procname}" in line:
            print(line)

def get_systemtime(soup):
    #print(soup)
    for element in soup.findAll("timecreated"):
        #print(element['systemtime'])
        pass

def get_log(dir_path, xml_file):
    with open(dir_path+xml_file, "r") as f:
        soup = BeautifulSoup(f, "html.parser")
    return soup

def get_file_name(dir_path):
    xml_list = os.listdir(dir_path)
    xml_list = [file for file in xml_list if file.endswith(".xml")]
    return xml_list

def start_sysmon():
    tool_path = os.path.join(os.getcwd(), "..", "SysinternalsSuite\\")
    tool = "Sysmon.exe"
    process = subprocess.Popen([f"{tool_path}{tool}","-accepteula","-i"])
    process.wait()
    clear_process = subprocess.Popen(["wevtutil", "cl", "Microsoft-Windows-Sysmon/Operational"])
    clear_process.wait()
    

def end_sysmon():
    tool_path = os.path.join(os.getcwd(), "..", "SysinternalsSuite\\")
    tool = "Sysmon.exe"
    
    uninstall_process = subprocess.Popen([f"{tool_path}{tool}","-accepteula","-u"])
    uninstall_process.wait()
    

def sysmon_with_evtx():
    current_path = os.getcwd()
    sysmon_log_path = os.path.join("C:\Windows\System32\winevt\Logs","Microsoft-Windows-Sysmon%4Operational.evtx")
    record_save_path = os.path.join(current_path,"sysmon_record_xml\\")

    with evtx.Evtx(sysmon_log_path) as log:
        id = 0
        for record in log.records():
            with open(record_save_path+f"sysmon_record{str(id)}.xml","w") as f:
                f.write(record.xml())
            id+=1

def main():
    record_save_path = os.path.join(os.getcwd(),"sysmon_record_xml\\")
    #noriben()
    start_sysmon()
    sysmon_with_evtx()
    xml_list = get_file_name(dir_path=record_save_path)
    for xml in xml_list:
        get_systemtime(get_log(dir_path=record_save_path, xml_file=xml))
    end_sysmon()


if __name__=="__main__":
    main()