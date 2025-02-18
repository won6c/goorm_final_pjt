import frida
import sys
import os
import json
import time
import copy
from common import stop_event
log_messages = {
    "process": {},
    "threads": {},
    "misc": []
}

JS_SCRIPT_PATH = os.path.join(os.getcwd(),"frida_py", "frida_stalker.js")

with open(JS_SCRIPT_PATH, "r", encoding='utf-8') as f:
    script_code = f.read()

#script_code+="\n"
#
#with open("interceptor_api.js","r",encoding='utf-8') as f:
#    script_code+=f.read()

def on_message(message, data):
    """Frida 스크립트에서 send()로 전달한 메시지를 처리하는 콜백 함수"""
    if message["type"] == "send":
        payload = message["payload"]
        etype = payload.get("type", "unknown")
        if etype in ("ProcessEvent",):
            pid = payload.get("pid")
            if pid is not None:
                log_messages["process"].setdefault(pid, []).append(payload)
        elif etype in ("ThreadEvent", "ThreadCall", "NewThreadCall", "CreateThread"):
            tid = payload.get("thread_id")
            if tid is not None:
                log_messages["threads"].setdefault(tid, []).append(payload)
            else:
                log_messages["misc"].append(payload)
        else:
            log_messages["misc"].append(payload)
    elif message["type"] == "error":
        print("[!] Error:", message["stack"])

def on_child_added(child):
    """자식 프로세스 생성 이벤트 처리 (자식 프로세스에도 동일한 스크립트 삽입)"""
    print("[*] Child process added: PID:", child.pid)
    try:
        child_session = frida.attach(child.pid)
        child_script = child_session.create_script(script_code)
        child_script.on("message", on_message)
        child_script.load()
        print("[*] Stalker script attached to child process", child.pid)
    except Exception as e:
        print("[-] Failed to attach stalker to child process:", e)


def process_stalker(session):
    #try:
    #    exe_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    #    pid = frida.spawn([exe_path])
    #    session = frida.attach(pid)
    #except Exception as e:
    #    print(f"[-] 프로세스 부착 실패: {e}")
    #    sys.exit(1)

    try:
        device = frida.get_local_device()
        device.on("child-added", on_child_added)
    except Exception as e:
        print(f"[-] 자식 프로세스 이벤트 등록 실패: {e}")

    try:   
        script = session.create_script(script_code)
    except Exception as e:
        print(f"[-] 스크립트 생성 실패: {e}")
        sys.exit(1)

    script.on("message", on_message)
    script.load()
    print("[*] 스크립트 로드 완료. 엔터를 누르면 종료합니다.")
    #frida.resume(pid)

    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        #result_dict_copy = copy.deepcopy(log_messages)
        #with open("stalker.json","w",encoding='utf-8') as f:
        #    json.dump(log_messages, f, indent=4)
        #print("KeyboardInterrupt received. Exiting...")
        session.detach()

    return log_messages


