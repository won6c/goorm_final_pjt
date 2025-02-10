import os

WATCH_DIR = "./monitor"

# 테스트할 파일 목록
test_files = {
    "test_document.docx": "This is a test document.",
    "test_image.jpg": "This is a fake image file.",
    "test_text.txt": "This is a simple text file.",
    "test_script.py": "print('Hello World!')",
}

# 폴더 생성
if not os.path.exists(WATCH_DIR):
    os.makedirs(WATCH_DIR)

# 테스트 파일 생성
for file_name, content in test_files.items():
    file_path = os.path.join(WATCH_DIR, file_name)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)

print("[INFO] 테스트 파일 생성 완료!")
