import frida
import sys
import time
import os
import re
from common import stop_event

log_messages = {}

JS_SCRIPT_PATH = os.path.join(os.getcwd(),"frida_py", "frida_hook.js")

def on_message(message, data):
    if message["type"] == "send":
        #print(message["payload"])
        payload = message["payload"]
        pattern = r"^\[(?P<time>[^\]]+)\]\s+(?P<dll>[^!]+)!(?P<function>.+)$"
        match = re.match(pattern, payload)
        if match:
            time_str = match.group("time")
            dll = match.group("dll")
            func = match.group("function")
            if time_str not in log_messages:
                log_messages[time_str] = []
            log_messages[time_str].append({"DLL": dll, "function": func})
    else:
        #print(message)
        pass

def on_detached(reason):
    print("[*] Process detached. Reason: %s" % reason)
    sys.exit(0)

def spawn_frida_to_process(file):
    pid = frida.spawn([file])
    return pid

def resume_frida_with_process(pid):
    try:
        session = frida.attach(pid)
        frida.resume(pid)
        return session
    except Exception as e:
        print(e)
        return None

def process_frida(session):
    session.on("detached", on_detached)
    
    with open(JS_SCRIPT_PATH, "r", encoding='utf-8') as f:
        js_code = f.read()
    try:
        script = session.create_script(js_code)
        script.on("message", on_message)
        script.load()
    except Exception as e:
        print(e)
        exit(1)
    
    print("[*] Hooking started. Press Ctrl+C to quit.")
    try:
        while not stop_event.is_set():
            time.sleep(1)

    except Exception as e:
        print(e)
        session.detach()
        print("\n[*] Detaching...")
    print("api")
    return {"API Hooking":log_messages}