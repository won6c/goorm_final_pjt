import os
import yara_rule
import analysis_pe
import subprocess

#print(os.listdir())

# 검사할 디렉토리 경로
scan_folder = "/home/kali/Desktop/sample"

def main():
    # YARA 룰 로드
    try:
        rules = yara_rule.load_yara_rules(yara_rule.rule_folder_path)
        print("✅ YARA 룰이 성공적으로 로드되었습니다.")
    except Exception as e:
        print(f"❌ YARA 룰 로드 중 오류 발생: {e}")
        return

    # 악성코드 탐지된 파일 목록 저장
    infected_files = yara_rule.scan_directory(scan_folder, rules)

    if infected_files:
        print("\n🔍 PE 분석을 시작합니다...")
        for file in infected_files:
            print(f"\n🎯 {file} 분석 진행...")
            analysis_pe.analyze_pe(file)

    # 바이러스토탈 검사 여부
    user_input = input("\n🔎 바이러스토탈(VirusTotal) 검사를 진행할까요? (yes/no): ").strip().lower()
    if user_input == "yes":
        print("\n🔍 바이러스토탈 검사 실행 중...")
        vt_script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "virusTotalAPI.py"))
        subprocess.run(["python", vt_script_path, scan_folder]) 

if __name__ == "__main__":
    main()
