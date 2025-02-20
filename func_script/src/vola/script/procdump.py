import subprocess
import os
import datetime

def create_memory_dump(process_name):
    """
    Procdump를 사용하여 메모리 덤프를 생성하는 함수
    :param process_name: 덤프를 생성할 프로세스 이름
    :return: 덤프 파일 경로
    """
    # 현재 날짜 및 시간으로 덤프 파일 이름 생성
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    dump_file_path = os.path.join(os.getcwd(), f"memory_dump_{timestamp}.dmp")

    # Procdump 실행 명령어
    cmd = ["C:\\Users\\User\\Desktop\\test\\SysinternalsSuite\\procdump.exe", process_name, "-ma", dump_file_path]

    try:
        print(f"Executing command: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)
        print(f"Memory dump created: {dump_file_path}")
        print(dump_file_path)
        return dump_file_path
    except Exception as e:
        print(f"Error: {e}")
        return dump_file_path

def process_procdump():
    process_name = "notepad"  # 예시로 'notepad' 프로세스를 사용
    dump_file = create_memory_dump(process_name)

    if dump_file:
        print(f"Memory dump saved to: {dump_file}")
        # 덤프 파일 경로를 Volatility 분석 스크립트로 넘겨줌
        # 예: run_volatility(dump_file) 
        return dump_file
    else:
        return "Error"