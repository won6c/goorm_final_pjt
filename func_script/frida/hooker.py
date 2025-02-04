import frida
import sys
import time
import os
import subprocess
import psutil

JS_SCRIPT_PATH = os.path.join(os.getcwd(), "frida_hook.js")

def on_message(message, data):
    if message["type"] == "send":
        print(message["payload"])
    else:
        print(message)

def on_detached(reason):
    print("[*] Process detached. Reason: %s" % reason)
    sys.exit(0)

def main():
    file = "C:\\Users\\User\\source\\repos\\malware\\x64\\Debug\\malware.exe"#os.path.join(os.getcwd(),"04.exe")
    #proc = subprocess.Popen(file, creationflags=subprocess.CREATE_NEW_CONSOLE)

    #target = proc.pid
    try:
        #pid = int(target)
        pid = frida.spawn([file])
        session = frida.attach(pid)
    except ValueError:
        #session = frida.attach(target)
        pass

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
        while True:
            time.sleep(1)
            if not psutil.pid_exists(pid):
                time.sleep(10)
                sys.exit(0)
    except Exception as e:
        print(e)
        session.detach()
        print("\n[*] Detaching...")
        
if __name__ == '__main__':
    main()
