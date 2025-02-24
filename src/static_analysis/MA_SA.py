from static_analysis.yara_rule import *
from static_analysis.analysis_pe import *
from static_analysis.virusTotalAPI import *
from CONFIG.config import SCAN_FOLDER

def process_MA_SA():
    # YARA 룰 로드
    try:
        rules = load_yara_rules(rule_folder_path)
        print("✅ YARA 룰이 성공적으로 로드되었습니다.")
    except Exception as e:
        print(f"❌ YARA 룰 로드 중 오류 발생: {e}")
        return

    # 악성코드 탐지된 파일 목록 저장
    infected_files = scan_directory(SCAN_FOLDER, rules)

    if infected_files:
        print("\n🔍 PE 분석을 시작합니다...")
        for file in infected_files:
            print(f"\n🎯 {file} 분석 진행...")
            pe_result = analyze_pe(file)

    # 바이러스토탈 검사 여부 
    #user_input = input("\n🔎 바이러스토탈(VirusTotal) 검사를 진행할까요? (yes/no): ").strip().lower()
    #if user_input == "yes":
    print("\n🔍 바이러스토탈 검사 실행 중...")
    vt_result = scan_files() #dict

    return_dict ={
        "infected_files":infected_files,
        "pe_analysis":pe_result,
        "vt_result":vt_result
    }

    return return_dict
