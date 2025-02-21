import os
import pefile

def extract_imports(file_path):
    """
    PE 파일의 import 목록을 추출하여 반환하는 함수.
    반환 값: ['kernel32.dll_CreateFileW', 'user32.dll_MessageBoxA', ...] 이런 식의 문자열 리스트
    """
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        print(f"Error parsing PE: {e}")
        return []

    imports_list = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors='ignore') if entry.dll else "UnknownDLL"
            for imp in entry.imports:
                func_name = None
                if imp.name:
                    func_name = imp.name.decode(errors='ignore')
                else:
                    func_name = "None"
                # 예: 'KERNEL32.dll_CreateFileW'
                combined = f"{dll_name}_{func_name}"
                imports_list.append(combined)
    return imports_list

def main():
    exe_folder = os.path.join(os.getcwd(), "malware_sample", "benign_dataset")
    max_section_count = 0
    max_section_file = None  # 섹션이 가장 많은 파일의 경로

    # exe_folder 내 모든 .exe 파일 찾기
    for fname in os.listdir(exe_folder):
        fpath = os.path.join(exe_folder, fname)
        if not os.path.isfile(fpath):
            continue

        # pefile 로 섹션 개수 확인
        try:
            pe = pefile.PE(fpath)
            section_count = len(pe.sections)
            if section_count > max_section_count:
                max_section_count = section_count
                max_section_file = fpath
        except Exception as e:
            print(f"Failed to parse {fpath}: {e}")

    # 결과 출력
    if max_section_file is None:
        print("No valid exe file found or no sections at all.")
        return

    print(f"가장 많은 섹션({max_section_count})을 가진 exe: {max_section_file}")
    
    # 해당 파일의 imports 출력
    imports_list = extract_imports(max_section_file)
    if not imports_list:
        print("No imports or failed to parse imports.")
    else:
        print("=== Imports ===")
        for imp_item in imports_list:
            print(imp_item)

if __name__ == "__main__":
    main()
