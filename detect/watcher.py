import os
import shutil
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WATCH_DIR = "./monitor"
BACKUP_DIR = "./backup"

# 로깅 설정 (콘솔에 DEBUG 메시지 출력, 백업 관련 메시지는 로그에 기록만)
logging.basicConfig(
    level=logging.DEBUG,  # DEBUG 메시지까지 출력
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),  # 콘솔 출력 (DEBUG 포함)
        logging.FileHandler('file_monitor.log')  # 파일로도 로그 기록 (INFO 이상)
    ]
)

class MonitorHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory:
            return

        file_path = event.src_path
        file_name = os.path.basename(file_path)
        new_size = os.path.getsize(file_path)

        logging.debug(f"파일 변경 감지됨: {file_path}")
        logging.debug(f"변경된 파일 크기: {new_size} bytes")

        # 백업 디렉토리 생성 확인
        if not os.path.exists(BACKUP_DIR):
            logging.info(f"백업 디렉토리가 존재하지 않아 생성합니다: {BACKUP_DIR}")
            os.makedirs(BACKUP_DIR)

        # 백업 파일 경로 지정 (타임스탬프 추가)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(BACKUP_DIR, f"{file_name}_{timestamp}.bak")

        # 백업 완료 메시지는 INFO 레벨로만 출력
        if os.path.exists(file_path):
            shutil.copy2(file_path, backup_file)
            logging.info(f"파일 백업 완료: {backup_file}")  # 백업 완료 메시지만 출력
        else:
            logging.error(f"원본 파일이 존재하지 않아 백업 실패: {file_path}")

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
