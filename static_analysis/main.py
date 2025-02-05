import os
import yara_rule
import analysis_pe

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

if __name__ == "__main__":
    main()
