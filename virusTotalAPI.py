import configparser
import requests

def load_api_key_from_config(config_path="config.ini"):
    """
    config.ini에서 [DEFAULT] 섹션의 API_KEY 값을 읽어와 반환.
    """
    config = configparser.ConfigParser()
    config.read(config_path)
    return config["DEFAULT"].get("API_KEY", "")

def get_virustotal_report(file_hash: str, api_key: str):

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})

        # 1. 샘플 파일명 (유저들이 파일 업로드 시 사용했던 이름 목록)
        file_names = attributes.get("names", [])
        
        # 2. 엔진별 분석 결과 (last_analysis_results)
        last_analysis_results = attributes.get("last_analysis_results", {})

        # 3. 마지막 분석 통계 (malicious / suspicious / harmless / undetected 등 카운트)
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        malicious_count = last_analysis_stats.get("malicious", 0)
        suspicious_count = last_analysis_stats.get("suspicious", 0)
        harmless_count = last_analysis_stats.get("harmless", 0)
        undetected_count = last_analysis_stats.get("undetected", 0)
        
        # 4. VirusTotal이 내부적으로 매긴 평판 점수 (reputation)
        #    일반적으로 양수면 안전, 음수면 위험도가 높다고 보기도 하지만, 반드시 절대적 기준은 아님
        vt_reputation = attributes.get("reputation", 0)
        
        # 5. 간단한 사용자 정의 점수(naive_score) 예시
        #    - 예: 악성(Malicious) 탐지 1건당 2점, 의심(Suspicious) 탐지 1건당 1점 부여
        naive_score = malicious_count * 2 + suspicious_count

        # ========== 출력 ==========
        print("===== VirusTotal Analysis Report =====")
        print(f"File Hash        : {file_hash}")
        if file_names:
            print(f"Sample Filenames : {file_names}")  # 여러 개일 수 있으므로 리스트로 출력
        print("--------------------------------------")
        print(f"Malicious Count  : {malicious_count}")
        print(f"Suspicious Count : {suspicious_count}")
        print(f"Harmless Count   : {harmless_count}")
        print(f"Undetected Count : {undetected_count}")
        print(f"VT Reputation    : {vt_reputation} (VirusTotal 내부 평판 점수)")
        print(f"Naive Score      : {naive_score} (단순 계산 예시)")
        print("--------------------------------------")

        # 6. 어떤 근거로 '악성' 또는 '의심' 판정을 했는지 세부 확인
        #    -> 악성(malicious)으로 잡은 백신 엔진과 진단명(result) 출력
        if malicious_count > 0:
            print("[Malicious으로 분류한 엔진 목록]")
            for engine, result_info in last_analysis_results.items():
                if result_info.get("category") == "malicious":
                    detection_name = result_info.get("result", "N/A")
                    print(f"  - {engine} : {detection_name}")

        #    -> 의심(suspicious)으로 분류한 엔진 리스트도 출력 가능
        if suspicious_count > 0:
            print("\n[Suspicious으로 분류한 엔진 목록]")
            for engine, result_info in last_analysis_results.items():
                if result_info.get("category") == "suspicious":
                    detection_name = result_info.get("result", "N/A")
                    print(f"  - {engine} : {detection_name}")

    else:
        # 요청 실패 시 (401: 인증 오류, 404: 해시 미존재, 429: Rate Limit 등)
        print(f"[Error] Status Code: {response.status_code}")
        print(f"[Error] Response  : {response.text}")

def main():
    # 테스트용 해시 (EICAR 테스트 파일 MD5)
    sample_hash = "44d88612fea8a8f36de82e1278abb02f"
    get_virustotal_report(sample_hash)

if __name__ == "__main__":
    main()
