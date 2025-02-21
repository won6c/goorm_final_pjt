import os
import subprocess
import json
import time

def is_process_running(process_name):
    """ 현재 실행 중인 프로세스 확인 """
    try:
        result = subprocess.check_output(['tasklist'], text=True)
        return process_name.lower() in result.lower()
    except subprocess.CalledProcessError:
        return False

def run_procdump_and_analyze(process_name):
    """ Procdump 실행 후 덤프 파일 생성 """
    procdump_path = r"C:\Users\User\Desktop\MEM\tool\procdump.exe"
    dump_filename = f"memory_dump_{time.strftime('%Y%m%d_%H%M%S')}.dmp"
    dump_path = os.path.join(r"C:\Users\User\Desktop\MEM", dump_filename)

    # Procdump 실행 전 프로세스 확인
    if not is_process_running(process_name):
        print(f"[-] Process '{process_name}' is not running. Please start it first.")
        return None

    cmd = [procdump_path, process_name, "-ma", dump_path]
    print(f"[*] Running Procdump: {' '.join(cmd)}")

    try:
        subprocess.run(cmd, check=True, text=True)
        print(f"[+] Memory dump created at {dump_path}")
        return dump_path
    except subprocess.CalledProcessError as e:
        print(f"[-] Error during Procdump execution: {e}")
        return None

def run_volatility(plugin, dump_file):
    """ Volatility3 실행 """
    if not os.path.exists(dump_file):
        print(f"[-] Memory dump file not found: {dump_file}")
        return None

    cmd = ["vol", "-f", dump_file, plugin]
    try:
        print(f"[*] Running Volatility plugin: {plugin}")
        result = subprocess.check_output(cmd, text=True)
        print(f"[+] Volatility output received ({len(result)} bytes)")
        return result
    except subprocess.CalledProcessError as e:
        print(f"[-] Error running plugin {plugin}: {e}")
        return None

def parse_to_json(text_data):
    """ Volatility 결과를 JSON 형식으로 변환 """
    lines = text_data.split("\n")
    data = []

    for line in lines:
        parts = line.split()
        if len(parts) >= 5 and parts[0].isdigit():
            process_data = {
                "PID": int(parts[0]),
                "Name": parts[1],
                "PPID": int(parts[2]),
                "Threads": int(parts[3]),
                "Handles": int(parts[4])
            }
            data.append(process_data)

    return data

def update_mid_result(json_data):
    """ mid_result.json 업데이트 """
    mid_result_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mid_result.json")

    # 기존 JSON 불러오기
    if os.path.exists(mid_result_path):
        with open(mid_result_path, "r", encoding="utf-8") as f:
            try:
                mid_result = json.load(f)
            except json.JSONDecodeError:
                mid_result = {}
    else:
        mid_result = {}

    # Volatility 분석 결과 추가
    mid_result["volatility_analysis"] = {"pslist": json_data}

    # JSON 다시 저장
    with open(mid_result_path, "w", encoding="utf-8") as f:
        json.dump(mid_result, f, indent=4)

    print(f"[+] Updated mid_result.json with Volatility analysis")

def run_volatility_analysis(process_name):
    """ Procdump 실행 후 Volatility 분석 """
    memory_dump = run_procdump_and_analyze(process_name)
    if not memory_dump:
        print("[-] Memory dump not found. Exiting analysis.")
        return

    plugin = "windows.pslist.PsList"
    result = run_volatility(plugin, memory_dump)

    if result:
        json_data = parse_to_json(result)
    else:
        json_data = []

    update_mid_result(json_data)
