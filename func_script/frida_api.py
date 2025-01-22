import frida
import datetime
import subprocess

def execute_malware(file_path):
    proc = subprocess.Popen(file_path,creationflags=subprocess.CREATE_NEW_CONSOLE)
    return proc.pid

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if isinstance(payload, dict):
            if "error" in payload:
                # 오류 메시지 처리
                print(f"[ERROR] [{payload['time']}] Module: {payload['module']}, API: {payload['api']}, Reason: {payload['reason']}")
            else:
                # 정상적인 API 호출 로그
                print(f"[{payload['time']}] Module: {payload['module']}, API: {payload['api']}")
        else:
            print(f"[INFO] {payload}")
    else:
        print(f"[OTHER] {message}")

def trace_all_apis(pid):
    try:
        session = frida.attach(pid)
        print(f"[*] Attached to process {pid}")

        # 스크립트 로드
        script = session.create_script("""
            var modules = Process.enumerateModules();
            modules.forEach(function (module) {
                var exports = module.enumerateExports();
                exports.forEach(function (exp) {
                    try {
                        Interceptor.attach(exp.address, {
                            onEnter: function (args) {
                                var time = new Date().toISOString();
                                send({
                                    module: module.name,
                                    api: exp.name || "Unnamed API",
                                    time: time
                                });
                            }
                        });
                    } catch (e) {
                        var time = new Date().toISOString();
                        send({
                            error: "Failed to hook",
                            module: module.name,
                            api: exp.name || "Unnamed API",
                            reason: e.message,
                            time: time
                        });
                    }
                });
            });
        """)

        script.on('message', on_message)
        script.load()
        print("[*] API tracing started. Press Enter to stop.")
        input()
        session.detach()
    except frida.ProcessNotFoundError:
        print("[Error] Process not found. Ensure the PID is correct.")
    except frida.TransportError:
        print("[Error] The connection was closed. Ensure the process is running.")
    except Exception as e:
        print(f"[Error] {e}")

if __name__ == "__main__":
    file_path = "C:\\\Program Files\\Bandizip\\Bandizip.exe"
    #file_path = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
    pid = execute_malware(file_path=file_path)
    trace_all_apis(pid)
