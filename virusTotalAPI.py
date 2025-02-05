import configparser
import requests

def load_api_key_from_config(config_path="config.ini"):
    config = configparser.ConfigParser()
    config.read(config_path)
    return config["DEFAULT"].get("VT_API_KEY")

def get_virustotal_report(file_hash: str):

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": load_api_key_from_config()}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})

        md5 = attributes.get("md5", "N/A")
        sha1 = attributes.get("sha1", "N/A")
        sha256 = attributes.get("sha256", "N/A")

        file_names = attributes.get("names", [])
        
        last_analysis_results = attributes.get("last_analysis_results", {})


        last_analysis_stats = attributes.get("last_analysis_stats", {})
        malicious_count = last_analysis_stats.get("malicious", 0)
        suspicious_count = last_analysis_stats.get("suspicious", 0)
        harmless_count = last_analysis_stats.get("harmless", 0)
        undetected_count = last_analysis_stats.get("undetected", 0)
        
        vt_reputation = attributes.get("reputation", 0)
        
        naive_score = malicious_count * 2 + suspicious_count

        # ========== 출력 ==========
        print("===== VirusTotal Analysis Report =====")
        print("[Hash Types]")
        print(f"File Hash (MD5)    : {md5}")
        print(f"File Hash (SHA1)   : {sha1}")
        print(f"File Hash (SHA256) : {sha256}")
        if file_names:
            print(f"Sample Filenames : {file_names}")
        print("--------------------------------------")
        print(f"Malicious Count  : {malicious_count}")
        print(f"Suspicious Count : {suspicious_count}")
        print(f"Harmless Count   : {harmless_count}")
        print(f"Undetected Count : {undetected_count}")
        print(f"VT Reputation    : {vt_reputation} (VirusTotal 내부 평판 점수)")
        print(f"Naive Score      : {naive_score} (단순 계산 예시)")
        print("--------------------------------------")

        if malicious_count > 0:
            print("[Malicious으로 분류한 엔진 목록]")
            for engine, result_info in last_analysis_results.items():
                if result_info.get("category") == "malicious":
                    detection_name = result_info.get("result", "N/A")
                    print(f"  - {engine} : {detection_name}")

        if suspicious_count > 0:
            print("\n[Suspicious으로 분류한 엔진 목록]")
            for engine, result_info in last_analysis_results.items():
                if result_info.get("category") == "suspicious":
                    detection_name = result_info.get("result", "N/A")
                    print(f"  - {engine} : {detection_name}")

    else:
        print(f"[Error] Status Code: {response.status_code}")
        print(f"[Error] Response  : {response.text}")

def main():
    sample_hash = "44d88612fea8a8f36de82e1278abb02f"
    get_virustotal_report(sample_hash)

if __name__ == "__main__":
    main()