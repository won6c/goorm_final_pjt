import os
import subprocess
import psutil
import time

procdump_path = r"C:\Users\User\Desktop\goorm_final_pjt-MA_DA_won6c\func_script\src\tools\procdump.exe"
target_process = "chrome.exe"
dump_file = "memory.dmp"

def get_process_pid(process_name):
    """ 실행 중인 프로세스 목록에서 특정 프로세스의 PID를 찾음 """
    for proc in psutil.process_iter(attrs=['pid', 'name']):
        if proc.info['name'].lower() == process_name.lower():
            return proc.info['pid']
    return None

def run_procdump_and_analyze():
    chrome_pid = get_process_pid(target_process)
    if chrome_pid:
        print(f"[INFO] {target_process}의 PID: {chrome_pid}")
        dump_command = f'"{procdump_path}" -ma {chrome_pid} {dump_file}'
        try:
            subprocess.run(dump_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if os.path.exists(dump_file):
                print(f"[+] {target_process} 메모리 덤프 생성 완료 → {dump_file}")
                # 덤프 파일 분석
                result_memory = analyze_memory(dump_file)
                return result_memory
            else:
                print("[ERROR] memory.dmp 파일이 생성되지 않았습니다.")
                return None
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] procdump 실행 실패: {e}")
            return None
    else:
        print(f"[ERROR] 실행 중인 {target_process} 프로세스를 찾을 수 없습니다.")
        return None

def analyze_memory(dump_file):
    # 메모리 분석 로직 추가
    # 예시로 덤프 파일을 분석 후 결과를 반환
    return {"analysis_result": "dummy result"}  # 실제 분석 결과로 변경
