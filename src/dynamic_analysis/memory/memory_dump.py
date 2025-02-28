import os
import subprocess
import psutil
import re
from CONFIG.config import DUMP_FILE, PROCDUMP_PATH

def read_memory_dump(dump_file):
    """메모리 덤프 파일을 바이너리로 읽기"""
    try:
        with open(dump_file, "rb") as f:
            return f.read()
    except Exception as e:
        print(f"Error: {e}")
        return None

def find_strings(data, min_length=4):
    """메모리에서 특정 길이 이상의 문자열 찾기"""
    pattern = rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}"
    return [match.group().decode(errors="ignore") for match in re.finditer(pattern, data)]

def find_process_names(data):
    """메모리에서 프로세스 이름 추출 (단순 검색)"""
    exe_pattern = rb"[a-zA-Z0-9_-]+\.exe"
    return list(set([match.group().decode(errors="ignore") for match in re.finditer(exe_pattern, data)]))

def find_dll_names(data):
    """메모리에서 DLL 파일명 추출"""
    dll_pattern = rb"[a-zA-Z0-9_-]+\.dll"
    return list(set([match.group().decode(errors="ignore") for match in re.finditer(dll_pattern, data)]))

def analyze_memory(dump_file):
    """메모리 덤프 분석 실행"""
    try:
        data = read_memory_dump(dump_file)
        if data is None:
            print("[ERROR] Failed to read memory dump!")
            return None

        print(f"\n[+] 분석 시작: {dump_file}")
        
        process_list = find_process_names(data)
        dll_list = find_dll_names(data)
        strings_found = find_strings(data)

        return {
            "process_list": process_list[:10],
            "dlls": dll_list[:10], 
            "strings": strings_found[:10]
        }

    except Exception as e:
        print(f"[ERROR] Error during memory analysis: {e}")
        return None

def get_process_pid(process_name):
    """ 실행 중인 프로세스 목록에서 특정 프로세스의 PID를 찾음 """
    for proc in psutil.process_iter(attrs=['pid', 'name']):
        if proc.info['name'].lower() == process_name.lower():
            return proc.info['pid']
    return None

def run_procdump_and_analyze(pid):
    chrome_pid = pid
    if chrome_pid:
        dump_command = [PROCDUMP_PATH, "-accepteula", "-ma", str(chrome_pid), DUMP_FILE]
        
        try:
            subprocess.run(dump_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except subprocess.CalledProcessError as e:
            pass
        if os.path.exists(DUMP_FILE):
            # 덤프 파일 분석
            result_memory = analyze_memory(DUMP_FILE)
            return result_memory
        else:
            print("[ERROR] memory.dmp 파일이 생성되지 않았습니다.")
            return None
