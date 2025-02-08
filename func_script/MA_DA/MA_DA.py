from dlls.dll_list import *
from frida_py.hooker import *
from frida_py.frida_stalker import *
from network.network_packet import *
from process.process_list import *
from reg.reg_capture_test import *
from vola.script.procdump import *
from common import stop_event
from concurrent.futures import ThreadPoolExecutor, as_completed
from event.event_security import *
from event.event_system import *
import os, time, psutil, copy

def wait_for_termination_or_timeout(pid, timeout=60):
    start_time = time.time()
    while True:
        if not psutil.pid_exists(pid):
            break
        elif time.time() - start_time > timeout:
            break
        time.sleep(1)

def signal_threads_to_stop():
    stop_event.set()

def process():
    file = os.path.join(os.getcwd(), "frida_py", "04.exe")

    before_capture = capture()
    process_time = time.time()
    with ThreadPoolExecutor(max_workers=6) as executor: # 함수를 추가할 수록 max_workers의 값을 추가하는 함수의 개수만큼 추가해야 함
        future_process_list = executor.submit(process_list)
        future_event_security_list = executor.submit(monitor_security_event_log,"localhost","Security",[4624, 4625, 4672])
        future_event_system_list = executor.submit(monitor_system_event_log,"localhost","System",[4624, 4625, 4672])
        time.sleep(5)
        pid = spawn_frida_to_process(file)
        future_network = executor.submit(process_network)
        session = resume_frida_with_process(pid)
        if not session:
            print("Process Not Executed or resume failed")
            exit(1)
        
        future_frida = executor.submit(process_frida, session)
        future_dll   = executor.submit(process_dll, pid)
        
        wait_for_termination_or_timeout(pid)
        signal_threads_to_stop()
        
        result_process_list = future_process_list.result()
        result_frida = future_frida.result()
        result_dll = future_dll.result()
        result_event_security = future_event_security_list.result()
        result_event_system = future_event_system_list.result()
        result_network = future_network.result()

    result_dict = {
        "process_list": result_process_list,
        "process_frida": result_frida,
        "process_dll": result_dll,
        "event_security":result_event_security,
        "event_system":result_event_system,
        "network_traffic":result_network,
    }

    after_capture = capture()
    reg_result = process_reg(before_capture=before_capture, after_capture=after_capture)
    result_dict[process_reg.__name__]=reg_result
    print("각 스레드의 결과값:")
    for func, res in result_dict.items():
        print(f"{func} -> {res}")
    print(f"Execution time : {time.time()-process_time}")

    result_dict_copy = copy.deepcopy(result_dict)
    with open('mid_result.json', 'w', encoding='utf-8') as f:
        json.dump(result_dict_copy, f, indent=4, ensure_ascii=False)
def main():
    process()

if __name__ == "__main__":
    main()
