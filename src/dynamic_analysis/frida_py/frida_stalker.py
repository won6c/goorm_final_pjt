import frida
import sys
import time
from dynamic_analysis.common import stop_event
from CONFIG.config import JS_SCRIPT_PATH

log_messages = {
    "process": {},
    "threads": {},
    "misc": {}
}


with open(JS_SCRIPT_PATH, "r", encoding="utf-8") as f:
    script_code = f.read()

def spawn_frida_to_process(file):
    pid = frida.spawn([file])
    return pid

def resume_frida_with_process(pid):
    try:
        session = frida.attach(pid)
        return session
    except Exception as e:
        print(e)
        return None

def on_message(message, data):
    """Frida 스크립트에서 send()로 전달한 메시지를 처리하는 콜백 함수"""
    if message["type"] == "send":
        payload = message["payload"]
        etype = payload.get("type", "unknown")
        if etype == "ProcessEvent":
            pid = payload.get("pid")
            if pid is not None:
                log_messages["process"].setdefault(pid, []).append(payload)
        else:
            tid = payload.get("thread_id")
            if tid is not None:
                log_messages["threads"].setdefault(tid, {"events": [], "details": [], "function or api": []})
                if etype in ("ThreadEvent", "ThreadCall", "CreateThread"):
                    log_messages["threads"][tid]["events"].append(payload)
                    if "target" in payload:
                        if payload["target"] is None:
                            if payload.get("module") and payload.get("address") and payload.get("module_base"):
                                try:
                                    moduleName = payload["module"]
                                    addr = int(payload["address"], 16)
                                    modBase = int(payload["module_base"], 16)
                                    offset = addr - modBase
                                    formatted = f"{moduleName}+0x{offset:x}"
                                except Exception as e:
                                    formatted = None
                            else:
                                formatted = None
                            log_messages["threads"][tid]["function or api"].append(formatted)
                        else:
                            log_messages["threads"][tid]["function or api"].append(payload["target"])
                else:
                    log_messages["threads"][tid]["details"].append(payload)
                    log_messages["threads"][tid]["function or api"].append(etype)
            else:
                log_messages["misc"].setdefault("default", []).append(payload)
    elif message["type"] == "error":
        #print("[!] Error:", message["stack"])
        pass




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

def on_detached(reason):
    print("[*] Process detached. Reason: %s" % reason)
    sys.exit(0)

def process_stalker(session):
    session.on("detached", on_detached)
    try:
        device = frida.get_local_device()
        device.on("child-added", on_child_added)
    except Exception as e:
        print(e)

    try:
        script = session.create_script(script_code)
        script.on("message", on_message)
        script.load()
    except Exception as e:
        print(e)
        exit(1)

    try:
        while not stop_event.is_set():
            time.sleep(1)
    except Exception as e:
        print(e)
        session.detach()

    for tid, misc_events in log_messages["misc"].items():
        if tid != "default":
            if tid in log_messages["threads"]:
                log_messages["threads"][tid] = {
                    "events": log_messages["threads"][tid],
                    "details": misc_events
                }
            else:
                log_messages["threads"][tid] = {"details": misc_events}

    for tid, thread_obj in log_messages["threads"].items():
        thread_obj["function or api"] = list(set(thread_obj["function or api"]))

    return log_messages
