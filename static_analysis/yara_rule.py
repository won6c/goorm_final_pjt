import yara
import os
import glob

# main.py 자신이 있는 폴더 경로
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# YARA Rules가 있는 폴더 경로
rule_folder_path = os.path.join(BASE_DIR, "..", "YARA_RULE")
rule_folder_path = os.path.abspath(rule_folder_path)

# YARA 룰 파일 로드 함수
def load_yara_rules(rule_folder):
    rule_files = glob.glob(os.path.join(rule_folder, "**", "**", "*.yara"), recursive=True) + \
                 glob.glob(os.path.join(rule_folder, '**', "**", '*.yar'), recursive=True) # 서브폴더 포함

    if not rule_files:
        raise FileNotFoundError(f"⚠️ {rule_folder} 폴더에서 YARA 룰 파일을 찾을 수 없습니다.")

    rules = yara.compile(filepaths={f"rule_{i}": rule for i, rule in enumerate(rule_files)})
    return rules

# 파일 분석 함수 (악성코드 종류 및 확률 출력)
def scan_file(file_path, rules):
    try:
        matches = rules.match(file_path)
        if matches:
            rules_names = [match.rule for match in matches] # 감지된 룰 이름 리스트
            print(f"\n⚠️ 악성코드 발견: {file_path}")
            for match in matches:
                rule_name = match.rule
                malware_type = match.meta.get('malware_family', 'Unknown')  # meta 정보가 없을 경우 'Unknown' 처리
                print(f"   - 룰: {rule_name}, 유형: {malware_type}")

            return True, file_path # 악성코드가 발견된 경우 파일 경로 반환
        else:
            print(f"✅ {file_path}는 안전합니다.")
        return False, None # 안전한 경우 None 반환
    except Exception as e:
        print(f"⚠️ 파일을 스캔하는 동안 오류가 발생했습니다: {e}")
        return False, None

# 디렉토리 스캔 함수 
def scan_directory(directory_path, rules):
    infected_files = []

    for root, dirs, files in os.walk(directory_path):
        for file in files:
            # .gitkeep 파일 제외
            if file == ".gitkeep":
                continue
            
            file_path = os.path.join(root, file)
            is_malicious, detected_file = scan_file(file_path, rules)
            if is_malicious:
                infected_files.append(detected_file)

    if infected_files:
        print("\n📊 감염된 파일 리스트:")
        for f in infected_files:
            print(f"   - {f}")
    else:
        print("\n✅ 악성코드가 탐지되지 않았습니다.")

    return infected_files  # 감염된 파일 리스트 반환