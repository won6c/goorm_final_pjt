import os
import csv
import pefile

def extract_imports(file_path):
    """
    PE 파일의 import 목록을 추출하여 반환.
    ['kernel32.dll_CreateFileW', 'user32.dll_MessageBoxA', ...] 형태의 문자열 리스트
    """
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        print(f"[Error] Parsing PE failed: {e}")
        return []

    imports_list = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors='ignore') if entry.dll else "UnknownDLL"
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode(errors='ignore')
                else:
                    func_name = "None"
                combined = f"{dll_name}_{func_name}"
                imports_list.append(combined)
    return imports_list

def main():
    # CSV 예시: [hash, year, filename, label] 형태 또는 사용자 상황에 맞춰 열 위치/이름 수정
    csv_path = os.path.join(os.getcwd(), "malware_sample","Malware_KIS", "KIS_label.csv")

    # EXE가 위치한 폴더. CSV에 들어있는 filename과 결합해서 실제 경로 만들 때 사용
    exe_folder = os.path.join(os.getcwd(), "malware_sample", "benign_dataset")

    # 1) CSV 읽어서 label=0(정상파일)만 대상 파일 목록으로 추출
    benign_files = []  # (filepath, filename) 형태로 저장
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            # 예: row = [hash, year, filename, label] 라고 가정
            if len(row) < 4:
                continue
            label = row[3]  # label이 0 또는 1
            if label == "0":  # 정상파일
                # row[2]가 실제 exe 파일 이름이라 가정
                exe_name = row[0]
                # exe_name 이 확장자 .exe 가 붙어있는지, 아니면 .vir 등인지 상황에 맞게 조정 필요
                exe_path = os.path.join(exe_folder, exe_name)
                if os.path.isfile(exe_path):
                    benign_files.append(exe_path)

    if not benign_files:
        print("정상파일(label=0)이 하나도 없거나, 경로가 잘못되었습니다.")
        return

    max_section_count = 0
    max_section_file = None

    # 2) 정상 파일들 중 섹션이 가장 많은 파일 찾기
    for fpath in benign_files:
        try:
            pe = pefile.PE(fpath)
            section_count = len(pe.sections)
            if section_count > max_section_count:
                max_section_count = section_count
                max_section_file = fpath
        except Exception as e:
            print(f"Failed to parse {fpath}: {e}")

    if max_section_file is None:
        print("정상파일 중 섹션 정보가 파싱된 파일이 없습니다.")
        return

    # 3) 결과 출력
    print(f"[결과] 정상파일 중 섹션이 가장 많은 파일: {max_section_file}")
    print(f"섹션 개수: {max_section_count}")

    # 4) 해당 파일 import 목록
    imports_list = extract_imports(max_section_file)
    if not imports_list:
        print("해당 파일의 import 정보가 없거나 추출 실패.")
    else:
        print("=== Import 목록 ===")
        for imp in imports_list:
            print(" ", imp)

if __name__ == "__main__":
    main()
