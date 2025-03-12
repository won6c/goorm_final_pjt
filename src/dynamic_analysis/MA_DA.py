from dynamic_analysis.dlls.dll_list import *
from dynamic_analysis.frida_py.frida_stalker import *
from dynamic_analysis.network.network_packet import *
from dynamic_analysis.detect.watchdog_src import *
from dynamic_analysis.reg.reg_capture import *
from dynamic_analysis.common import stop_event
from concurrent.futures import ThreadPoolExecutor
from dynamic_analysis.event.event_security import *
from dynamic_analysis.event.event_system import *
from dynamic_analysis.identify import *
from dynamic_analysis.memory.memory_dump import *
import time, psutil, copy, frida
from CONFIG.config import MID_RESULT_PATH, TIMEOUT

def wait_for_termination_or_timeout(pid, timeout=TIMEOUT):
    start_time = time.time()
    while True:
        if not psutil.pid_exists(pid):
            break
        elif time.time() - start_time > timeout:
            break
        time.sleep(1)

def signal_threads_to_stop():
    stop_event.set()

def process_MA_DA():
    file = sys.argv[1]

    before_capture = capture()
    process_time = time.time()
    with ThreadPoolExecutor(max_workers=6) as executor: # 함수를 추가할 수록 max_workers의 값을 추가하는 함수의 개수만큼 추가해야 함
        future_watchdog = executor.submit(start_watcher)
        future_event_security_list = executor.submit(monitor_security_event_log,"localhost","Security",[4624, 4625, 4672])
        future_event_system_list = executor.submit(monitor_system_event_log,"localhost","System",[6005, 6006, 7001, 7036])
        time.sleep(5)
        pid = spawn_frida_to_process(file)
        future_network = executor.submit(process_network)
        session = resume_frida_with_process(pid)
        future_frida = executor.submit(process_stalker, session)
        frida.resume(pid)
        if not session:
            print("Process Not Executed or resume failed")
            exit(1)
        
        future_dll   = executor.submit(process_dll, pid)
        future_memory = executor.submit(run_procdump_and_analyze,pid)
        
        wait_for_termination_or_timeout(pid)
        signal_threads_to_stop()
        
        result_frida = future_frida.result()
        result_dll = future_dll.result()
        result_event_security = future_event_security_list.result()
        result_event_system = future_event_system_list.result()
        result_network = future_network.result()
        result_watchdog = future_watchdog.result()
        result_memory = future_memory.result()

    result_dict = {
        "process_frida": result_frida,
        "process_dll": result_dll,
        "event_security":result_event_security,
        "event_system":result_event_system,
        "network_traffic":result_network,
        "watchdog":result_watchdog,
        "memory":result_memory
    }

    after_capture = capture()
    reg_result = process_reg(before_capture=before_capture, after_capture=after_capture)
    result_dict[process_reg.__name__]=reg_result

    print(f"Execution time : {time.time()-process_time}")

    result_dict_copy = copy.deepcopy(result_dict)
    final_type = print_result(result_dict_copy)
    result_dict_copy["final_type"] = final_type
    with open(MID_RESULT_PATH, 'w', encoding='utf-8') as f:
        json.dump(result_dict_copy, f, indent=4, ensure_ascii=False)
    return result_dict_copy
