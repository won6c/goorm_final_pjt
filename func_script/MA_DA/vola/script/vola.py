import subprocess
import os
import json

def run_volatility(plugin, dump_file, output_file=None):
    """
    Volatility3 플러그인을 실행하는 함수
    :param plugin: 실행할 플러그인 이름
    :param dump_file: 분석할 메모리 덤프 파일 경로
    :param output_file: 결과를 저장할 파일 경로 (기본값: None)
    :return: 분석 결과 텍스트
    """
    cmd = ["vol", "-f", dump_file, plugin]

    try:
        print(f"Executing command: {' '.join(cmd)}")
        result = subprocess.check_output(cmd, text=True)

        # 텍스트 출력 결과 저장
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result)

        return result
    except subprocess.CalledProcessError as e:
        return f"Error running plugin {plugin}: {e.output}"

def parse_to_json(input_file, output_file):
    """
    텍스트 파일을 JSON으로 변환하는 함수
    :param input_file: 입력 텍스트 파일 경로
    :param output_file: 출력 JSON 파일 경로
    """
    with open(input_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    data = {}
    for line in lines:
        if ":" in line:  # '키: 값' 형태의 줄만 파싱
            key, value = map(str.strip, line.split(":", 1))
            data[key] = value

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def main():
    memory_dump = os.path.join(os.getcwd(),"memory_dump.raw")
    output_dir = os.getcwd()

    # 결과 저장 폴더 생성
    os.makedirs(output_dir, exist_ok=True)

    # 실행할 플러그인
    plugins = ["windows.info", "windows.pslist.PsList", "windows.netstat.NetStat"]

    print("=== Starting Memory Analysis ===")
    for plugin in plugins:
        print(f"\n[+] Running {plugin}...")

        # 텍스트 결과 파일 경로
        txt_file = os.path.join(output_dir, f"{plugin.split('.')[-1]}.txt")
        
        # 플러그인 실행
        result = run_volatility(plugin, memory_dump, output_file=txt_file)
        print(result)

        # JSON 변환 파일 경로
        json_file = os.path.join(output_dir, f"{plugin.split('.')[-1]}.json")
        
        # 텍스트를 JSON으로 변환
        print(f"[+] Converting {txt_file} to JSON...")
        parse_to_json(txt_file, json_file)
        print(f"[+] JSON saved to {json_file}")

if __name__ == "__main__":
    main()