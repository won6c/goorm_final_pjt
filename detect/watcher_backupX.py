import os
import time
import logging
import subprocess
import base64
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WATCH_DIRS = [
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/AppData/Local"),
    os.path.expanduser("~/Documents")
]
EXIFTOOL_PATH = "C:\\tools\\exiftool.exe"  # exiftool의 절대 경로

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

        # 특정 확장자 제외
        exclude_extensions = [".index", ".ft", ".intermediate.txt"]
        if any(file_name.endswith(ext) for ext in exclude_extensions):
            return

        logging.debug(f"파일 변경 감지됨: {file_path}")
        
        # 문자열 분석 실행
        suspicious_strings = self.analyze_strings(file_path)
        if suspicious_strings:
            logging.warning(f"의심스러운 문자열 발견 ({file_name}): {suspicious_strings}")
        else:
            logging.info(f"파일 ({file_name})에서 의심스러운 문자열 없음.")

        # 메타데이터 분석 실행
        metadata = self.analyze_metadata(file_path)
        if metadata:
            logging.info(f"{file_name} 메타데이터 분석 결과(Base64 변환됨):\n{metadata}")

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

    def analyze_metadata(self, file_path):
        """ 파일의 메타데이터를 분석하는 함수 (Base64 변환 적용) """
        try:
            absolute_path = os.path.abspath(file_path)

            if not os.path.exists(absolute_path):
                logging.error(f"파일 경로가 존재하지 않습니다: {absolute_path}")
                return None

            result = subprocess.run([EXIFTOOL_PATH, absolute_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            if result.stderr:
                logging.error(f"exiftool 오류 ({absolute_path}): {result.stderr.decode(errors='ignore')}")

            metadata_output = result.stdout
            if not metadata_output:
                logging.error(f"{absolute_path}에 메타데이터가 없습니다.")
                return None

            encoded_metadata = base64.b64encode(metadata_output).decode('utf-8')
            return encoded_metadata
        except Exception as e:
            logging.error(f"메타데이터 분석 오류 ({file_path}): {e}")
            return None


def main():
    event_handler = MonitorHandler()
    observer = Observer()

    for watch_dir in WATCH_DIRS:
        if not os.path.exists(watch_dir):
            os.makedirs(watch_dir, exist_ok=True)
        observer.schedule(event_handler, watch_dir, recursive=False)

    observer.start()
    logging.info(f"파일 감시 시작: {', '.join(WATCH_DIRS)}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()