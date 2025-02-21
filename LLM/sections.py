import os
import pefile

def print_pe_sections(file_path):
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        print(f"[Error] PE parsing failed for {file_path}: {e}")
        return

    print(f"=== Sections in {os.path.basename(file_path)} ===")
    if not hasattr(pe, 'sections') or not pe.sections:
        print("No section information found.")
        return

    for idx, section in enumerate(pe.sections):
        # 섹션 이름은 b'.text\x00\x00' 처럼 바이트이므로, decode 후 문자열 정리
        section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        virtual_size = section.Misc_VirtualSize
        raw_size     = section.SizeOfRawData
        entropy      = section.get_entropy()  # pefile에서 제공하는 섹션 엔트로피 계산 메서드

        print(f"[Section {idx}] Name: {section_name}")
        print(f"    Virtual Size : {virtual_size}")
        print(f"    Raw Size     : {raw_size}")
        print(f"    Entropy      : {entropy:.4f}")
        print()

if __name__ == "__main__":
    file_path = r"C:\Users\yungh\바탕 화면\Malware_AI\malware_sample\benign_dataset\A593689BC261B07004D350A09BE95F4B27868F687D492F535851FD6ABF7E5B68"
    print_pe_sections(file_path)
