import subprocess
import os
import signal
import time

def capture_with_tshark(tool):
    ip_addr=" 10.0.2.15"
    try:
        process = subprocess.Popen([tool,"-i","Ethernet","-w", "capture_output.pcap"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        time.sleep(10)
        end_capture(process=process)
    except Exception as e:
        print(e)
    except KeyboardInterrupt:
        process.terminate()

def end_capture(process):
    try:
        process.send_signal(signal.CTRL_C_EVENT)
        process.wait()
    except Exception as e:
        print(e)
        process.terminate()        

def main():
    tool_path = "C:\Program Files\Wireshark\\"
    tool = "tshark.exe"
    tool = os.path.join(tool_path,tool)
    capture_with_tshark(tool)

if __name__=="__main__":
    main()