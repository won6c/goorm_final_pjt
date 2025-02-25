import sys
import re
import struct

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
    pattern = rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}"  # ASCII 범위 내 문자열 찾기
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
            return None  # 데이터를 읽지 못하면 None 반환

        print(f"\n[+] 분석 시작: {dump_file}")
        
        # 프로세스, DLL, 문자열 분석
        process_list = find_process_names(data)
        dll_list = find_dll_names(data)
        strings_found = find_strings(data)

        # 결과 출력 (디버깅용)
        print("\n[+] 분석 완료.")
        print(f"Processes: {process_list}")
        print(f"DLLs: {dll_list}")
        print(f"Strings: {strings_found}")

        # 결과를 딕셔너리로 반환
        return {
            "process_list": process_list[:10],  # 상위 10개만 반환
            "dlls": dll_list[:10],  # 상위 10개만 반환
            "strings": strings_found[:10]  # 상위 10개만 반환
        }

    except Exception as e:
        print(f"[ERROR] Error during memory analysis: {e}")
        return None  # 예외 발생 시 None 반환

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python mem_analyzer.py <memory_dump>")
        sys.exit(1)
    
    result = {"process_list": ["chrome.exe", "explorer.exe"], "dlls": ["ntdll.dll", "kernel32.dll"]}   

    
    analyze_memory(sys.argv[1])
