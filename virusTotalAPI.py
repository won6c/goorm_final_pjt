import configparser
import requests
import json
import sys
import os

# static_analysis 폴더 경로 추가
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "static_analysis")))
from analysis_pe import get_file_hashes # 해시값 불러오기
from main import scan_folder # 검사할 파일 경로 가져오기

# API 키 로드
def load_api_key_from_config(): # config_path="./config.ini"
    script_dir = os.path.dirname(os.path.abspath(__file__)) # 현재 스크립트 위치
    config_path = os.path.join(script_dir, "config.ini") # 절대 경로 설정

    config = configparser.ConfigParser()
    config.read(config_path)
    # print(f"🔍 config.ini 파일 로드 시도: {config_path}") # 경로 확인용
    return config["DEFAULT"].get("VT_API_KEY")

# VirusTotal 검사
def get_virustotal_report(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": load_api_key_from_config()}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        last_analysis_results = attributes.get("last_analysis_results", {})

        malicious_count = last_analysis_stats.get("malicious", 0)
        suspicious_count = last_analysis_stats.get("suspicious", 0)
        naive_score = malicious_count * 2 + suspicious_count

        malicious_engines = {
            engine: result_info.get("result", "N/A")
            for engine, result_info in last_analysis_results.items()
            if result_info.get("category") == "malicious"
        }

        suspicious_engines = {
            engine: result_info.get("result", "N/A")
            for engine, result_info in last_analysis_results.items()
            if result_info.get("category") == "suspicious"
        }

        result = {
            "MD5": attributes.get("md5", "N/A"),
            "SHA1": attributes.get("sha1", "N/A"),
            "SHA256": attributes.get("sha256", "N/A"),
            "Filenames": attributes.get("names", []),
            "Malicious_Count": malicious_count,
            "Suspicious_Count": suspicious_count,
            "Harmless_Count": last_analysis_stats.get("harmless", 0),
            "Undetected_Count": last_analysis_stats.get("undetected", 0),
            "VT_Reputation(VirusTotal 내부 평판 점수)": attributes.get("reputation", 0),
            "Naive Score(단순 계산 예시)": naive_score,
            "Malicious_Engines": malicious_engines,
            "Suspicious_Engines": suspicious_engines,
        }

        return result
    else:
        return {"Error": f"Status Code: {response.status_code}", "Response": response.text}

# 파일 목록 가져와서 검사 실행
def scan_files(scan_folder_arg = None):
    global scan_folder  # 전역 변수 사용
    if scan_folder_arg:
        scan_folder = scan_folder_arg

    # scan_folder가 None이면 종료
    if not scan_folder:
        print("[!] 검사할 폴더가 지정되지 않았습니다.")
        return

    # scan_folder가 문자열(폴더 경로)이면, 그 폴더 안의 파일 목록을 리스트로 변환
    if isinstance(scan_folder, str):
        if os.path.isdir(scan_folder): # scan_folder가 폴더인지 확인
            scan_folder = [
                os.path.join(scan_folder, f) for f in os.listdir(scan_folder) 
                if os.path.isfile(os.path.join(scan_folder, f)) and not f.endswith(".json") # JSON 파일 제외
            ]

    results = {}

    for file_path in scan_folder:
        if not os.path.isfile(file_path):
            print(f"[!] 파일을 찾을 수 없음: {file_path}")
            continue

        hashes = get_file_hashes(file_path) # 해시값 계산
        if "SHA256" not in hashes:
            print(f"[!] 해시값 계산 실패: {file_path}")
            continue

        sha256 = hashes["SHA256"]

        print(f"\n🔍 파일 검사 중: {file_path}")

        vt_result = get_virustotal_report(sha256)
        results[file_path] = vt_result

    # JSON 파일 저장
    file_name = os.path.basename(file_path)
    output_path = f"{file_name}.json"
    with open(output_path, "w", encoding="utf-8") as json_file:
        json.dump(results, json_file, indent=4, ensure_ascii=False)

    print(f"✅ 검사 결과 저장 완료: {output_path}")

if __name__ == "__main__":
    scan_folder_arg = sys.argv[1] if len(sys.argv) > 1 else None
    scan_files(scan_folder_arg)