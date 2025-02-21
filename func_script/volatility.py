import psutil
import subprocess
import time
import os
import json

def get_chrome_pid():
    """ 실행 중인 chrome.exe 프로세스 목록에서 PID를 가져옵니다. """
    chrome_pids = []
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == 'chrome.exe':
            chrome_pids.append(proc.info['pid'])
    
    if chrome_pids:
        # 가장 최근에 실행된 chrome.exe 프로세스를 선택
        return chrome_pids[-1]
    return None

def run_procdump_and_analyze(process_name, dump_folder):
    """ Procdump를 실행하고 메모리 덤프를 생성하는 함수 """
    procdump_path = r"C:\Users\User\Desktop\goorm_final_pjt-MA_DA_won6c\func_script\tool\procdump.exe"
    dump_filename = "memory_dump.dmp"
    dump_path = os.path.join(dump_folder, dump_filename)

    pid = "5940"  # 테스트를 위해 하드코딩

    cmd = [procdump_path, "-accepteula", "-ma", pid, dump_path]
    print(f"[*] Running Procdump: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(f"[+] Procdump Output:\n{result.stdout}")
        print(f"[+] Procdump Error:\n{result.stderr}")
        
        if os.path.exists(dump_path) and os.path.getsize(dump_path) > 0:
            print(f"[✔] Memory dump created successfully at: {dump_path}")
            return dump_path
        else:
            print(f"[-] Procdump failed: Dump file was not created properly.")
            return None
    except Exception as e:
        print(f"[-] Exception occurred: {e}")
        return None

def update_mid_result(dump_path):
    """ mid_result 파일 업데이트 """
    mid_result_path = "mid_result.json"
    print(f"[*] Updating mid_result.json with new dump path")
    data = {"last_dump": dump_path}
    with open(mid_result_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

# ✅ 오류 수정: 함수 이름을 올바르게 변경하여 호출
if __name__ == "__main__":
    process_name = "chrome.exe"
    dump_folder = r"C:\Users\User\Desktop\goorm_final_pjt-MA_DA_won6c\func_script"
    
    # run_procdump() → run_procdump_and_analyze() 로 변경
    dump_path = run_procdump_and_analyze(process_name, dump_folder)

    if dump_path:
        update_mid_result(dump_path)
