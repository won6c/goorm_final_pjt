import os
import time
import subprocess
import base64
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from dynamic_analysis.common import stop_event
from CONFIG.config import EXIFTOOL_PATH, STRINGS_PATH, IGNORED_EXTENSIONS, LOG_THROTTLE_TIME, WATCH_DIRS

last_logged = {}
log_messages = []

def should_log(file_path):
    """로그를 남겨야 하는지 확인하는 함수."""
    ext = os.path.splitext(file_path)[-1].lower()
    if ext in IGNORED_EXTENSIONS:
        return False
    now = time.time()
    if file_path in last_logged and (now - last_logged[file_path] < LOG_THROTTLE_TIME):
        return False
    last_logged[file_path] = now
    return True

class MonitorHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory or stop_event.is_set():  # <- Stop 이벤트 감지 추가
            return

        file_path = event.src_path
        file_name = os.path.basename(file_path)
        
        if not os.path.exists(file_path) or not should_log(file_path):
            return

        file_size = os.path.getsize(file_path)

        # Perform string analysis
        strings_result = self.analyze_strings(file_path) if file_size <= 100 * 1024 * 1024 else {"error": "File too large for analysis"}
        
        # Perform metadata analysis
        metadata_result = self.analyze_metadata(file_path)

        result_data = {
            "file_name": file_name,
            "file_path": file_path,
            "file_size": file_size,
            "analysis": {
                "strings": strings_result,
                "metadata": metadata_result
            }
        }

        log_messages.append(result_data)

    def analyze_strings(self, file_path):
        """파일 내부 문자열 분석"""
        try:
            file_path_cp949 = file_path.encode('cp949', errors='ignore').decode('cp949')
            result = subprocess.run(
                [STRINGS_PATH, file_path_cp949], 
                capture_output=True, text=True, encoding='cp949', errors='ignore'
            )
            strings_output = result.stdout
            suspicious_strings = [
                line for line in strings_output.splitlines() if "http" in line or "cmd" in line or "powershell" in line
            ]
            return suspicious_strings
        except Exception as e:
            return {"error": str(e)}

    def analyze_metadata(self, file_path):
        """파일 메타데이터 분석 (Base64 인코딩)"""
        try:
            absolute_path = os.path.abspath(file_path)
            if not os.path.exists(absolute_path):
                return {"error": "File path does not exist"}

            file_path_cp949 = absolute_path.encode('cp949', errors='ignore').decode('cp949')

            result = subprocess.run(
                [EXIFTOOL_PATH, file_path_cp949], 
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )

            stderr_output = result.stderr.decode(errors='ignore').strip()
            metadata_output = result.stdout

            if stderr_output:
                return {"error": stderr_output}

            if not metadata_output:
                return {"error": "No metadata found"}

            return {"metadata_base64": base64.b64encode(metadata_output).decode('utf-8')}
        except Exception as e:
            return {"error": str(e)}

def start_watcher():
    """파일 감시를 실행하는 함수 (스레드 종료 감지 포함)"""
    event_handler = MonitorHandler()
    observer = Observer()

    for watch_dir in WATCH_DIRS:
        if not os.path.exists(watch_dir):
            continue
        observer.schedule(event_handler, watch_dir, recursive=False)

    observer.start()

    try:
        while not stop_event.is_set():  # <- stop_event 감지해서 종료 처리
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()

        return log_messages