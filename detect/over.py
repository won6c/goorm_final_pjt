import os
import random

# 랜덤 데이터로 덮어쓸 파일 경로
TARGET_FILE = "./monitor/test_text.txt"  # 변경 가능

def overwrite_with_random_data(file_path, size=1024):
    """파일을 랜덤 바이너리 데이터로 덮어쓰기"""
    try:
        with open(file_path, "wb") as f:
            f.write(os.urandom(size))  # size 바이트만큼 랜덤 데이터 기록
        print(f"[INFO] {file_path} 파일을 {size} 바이트의 랜덤 데이터로 덮어씀.")
    except Exception as e:
        print(f"[ERROR] {e}")

# 실행
overwrite_with_random_data(TARGET_FILE)
