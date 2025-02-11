import os
import shutil
import time
import logging
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WATCH_DIR = "./monitor"
BACKUP_DIR = "./backup"

# 로깅 설정
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('file_monitor.log')
    ]
)

class MonitorHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory:
            return

        file_path = event.src_path
        file_name = os.path.basename(file_path)

        logging.debug(f"파일 변경 감지됨: {file_path}")

        # 백업 수행
        backup_file = self.backup_file(file_path)
        if backup_file:
            logging.info(f"파일 백업 완료: {backup_file}")

            # 문자열 분석 실행
            suspicious_strings = self.analyze_strings(file_path)
            if suspicious_strings:
                logging.warning(f"의심스러운 문자열 발견 ({file_name}): {suspicious_strings}")
            else:
                logging.info(f"파일 ({file_name})에서 의심스러운 문자열 없음.")

    def backup_file(self, file_path):
        """ 파일을 백업하는 함수 """
        if not os.path.exists(BACKUP_DIR):
            os.makedirs(BACKUP_DIR)

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        file_name = os.path.basename(file_path)
        backup_file = os.path.join(BACKUP_DIR, f"{file_name}_{timestamp}.bak")

        if os.path.exists(file_path):
            shutil.copy2(file_path, backup_file)
            return backup_file
        else:
            logging.error(f"백업 실패 (파일 없음): {file_path}")
            return None

    def analyze_strings(self, file_path):
        """ 파일 내부의 문자열을 분석하는 함수 """
        try:
            result = subprocess.run(['strings', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            strings_output = result.stdout.decode('utf-8', errors='ignore')

            # 의심스러운 문자열 필터링
            suspicious_strings = [line for line in strings_output.splitlines() if "http" in line or "cmd" in line or "powershell" in line]
            return suspicious_strings
        except Exception as e:
            logging.error(f"문자열 분석 오류 ({file_path}): {e}")
            return None

def main():
    if not os.path.exists(WATCH_DIR):
        os.makedirs(WATCH_DIR)

    event_handler = MonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=False)
    observer.start()

    logging.info(f"파일 감시 시작: {WATCH_DIR}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
