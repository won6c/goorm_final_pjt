import yara
import os
import glob

# ReversingLabs YARA Rules가 있는 폴더 경로
rule_folder_path = "../YARA_RULE"

# YARA 룰 파일 로드 함수
def load_yara_rules(rule_folder):
    rule_files = glob.glob(os.path.join(rule_folder, "**", "**", "*.yara"), recursive=True) + \
                 glob.glob(os.path.join(rule_folder, '**', "**", '*.yar'), recursive=True) # 서브폴더 포함

    if not rule_files:
        raise FileNotFoundError(f"⚠️ {rule_folder} 폴더에서 YARA 룰 파일을 찾을 수 없습니다.")

    rules = yara.compile(filepaths={f"rule_{i}": rule for i, rule in enumerate(rule_files)})
    return rules

# YARA 룰 로드 시도
try:
    rules = load_yara_rules(rule_folder_path)
    print("✅ YARA 룰이 성공적으로 로드되었습니다.")
except FileNotFoundError as e:
    print(e)
except yara.Error as e:
    print(f"❌ YARA 룰 로드 중 오류 발생: {e}")

# 파일 분석 함수 (악성코드 종류 및 확률 출력)
def scan_file(file_path, rules):
    try:
        matches = rules.match(file_path)
        if matches:
            print(f"\n⚠️ 악성코드 발견: {file_path}")
            for match in matches:
                rule_name = match.rule
                malware_type = match.meta.get('malware_family', 'Unknown')  # meta 정보가 없을 경우 'Unknown' 처리
                print(f"   - 룰: {rule_name}, 유형: {malware_type}")
        else:
            print(f"✅ {file_path}는 안전합니다.")
        return len(matches)  # 탐지된 룰 개수 반환
    except Exception as e:
        print(f"⚠️ 파일을 스캔하는 동안 오류가 발생했습니다: {e}")
        return 0

# 디렉토리 스캔 함수 (악성코드 탐지 확률 계산)
def scan_directory(directory_path, rules):
    total_files = 0
    infected_files = 0

    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            total_files += 1
            if scan_file(file_path, rules) > 0:
                infected_files += 1

    if total_files > 0:
        infection_rate = (infected_files / total_files) * 100
        print(f"\n📊 총 {total_files}개 파일 중 {infected_files}개가 악성코드로 판정되었습니다.")
        print(f"🛑 악성코드 감염 확률: {infection_rate:.2f}%")
    else:
        print("\n📂 검사할 파일이 없습니다.")

# YARA 룰이 성공적으로 로드되었을 때만 스캔 실행
if rules:
    scan_directory('/home/kali/Desktop/sample', rules)
else:
    print("⚠️ YARA 룰을 로드하지 못했으므로 스캔을 실행할 수 없습니다.")