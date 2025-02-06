import struct
import pefile  # pip install pefile
import subprocess
import os
from suspicious import suspicious_apis, packing_signatures
import hashlib
import magic # pip install python-magic

# 파일 타입 확인
def get_file_type(file_path):
    if not os.path.exists(file_path):
        return f"❌ 오류: '{file_path}' 파일이 존재하지 않습니다."

    try:
        with open(file_path, "rb") as f:
            file_type = magic.from_buffer(f.read(2048), mime=True)
        extension = os.path.splitext(file_path)[1]  # 파일 확장자 추출
        print(f"📄 파일: {file_path}\n📂 확장자: {extension}\n🔍 MIME 타입: {file_type}")
    except Exception as e:
        print(f"에러 발생: {e}")

# 패킹 시그니처 확인
def detect_packing_signature(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        detected_packers = []
        for packer, signature in packing_signatures.items():
            if signature in data:
                detected_packers.append(packer)

        if detected_packers:
            print(f"⚠️ 탐지된 패킹 시그니처: {', '.join(detected_packers)}")
            return detected_packers
        else:
            print("✅ 패킹 시그니처 없음.")
            return None
    except FileNotFoundError:
        print("파일을 찾을 수 없습니다.")
    except Exception as e:
        print(f"에러 발생: {e}")

# UPX 패킹된 파일 자동 언패킹
def unpack_upx(file_path):
    try:
        unpacked_path = file_path.replace(".exe", "_unpacked.exe")
        result = subprocess.run(["upx", "-d", file_path, "-o", unpacked_path], capture_output=True, text=True)
        if "Unpacked" in result.stdout:
            print(f"✅ UPX 언패킹 완료: {unpacked_path}")
            return unpacked_path
        else:
            print("❌ UPX 언패킹 실패. 직접 확인 필요.")
            return None
    except FileNotFoundError:
        print("⚠️ UPX가 설치되지 않았습니다. 'upx' 명령어를 사용할 수 있는지 확인하세요.")
    except Exception as e:
        print(f"에러 발생: {e}")

# 패킹 여부 확인 및 언패킹
def check_packing(file_path):
    try:
        pe = pefile.PE(file_path)

        packed_sections = []
        for section in pe.sections:
            section_name = section.Name.decode().strip("\x00")
            entropy = section.get_entropy()
            print(f"  [섹션] {section_name} - 크기: {section.SizeOfRawData} 바이트, 엔트로피: {entropy:.2f}")

            if "UPX" in section_name.upper() or entropy > 7.5:
                packed_sections.append(section_name)

        if packed_sections:
            print(f"⚠️ 패킹 가능성 높은 섹션 발견: {packed_sections}")

            # 패킹 시그니처 확인
            detected_packing = detect_packing_signature(file_path)

            # UPX 패킹된 경우 자동 언패킹
            with open(file_path, "rb") as f:
                data = f.read()
                if b'UPX!' in data:
                    print("⚠️ UPX 패킹된 파일입니다! 자동으로 언패킹을 시도합니다...")
                    unpacked_file = unpack_upx(file_path)
                    if unpacked_file:
                        print(f"🔄 언패킹된 파일: {unpacked_file}")
                        return unpacked_file 

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            num_imports = sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
            print(f"  Import된 함수 개수: {num_imports}")
            if num_imports < 5:
                print("⚠️ Import된 함수 개수가 적어 패킹 가능성이 있음!")
    
    except FileNotFoundError:
        print("파일을 찾을 수 없습니다.")
    except pefile.PEFormatError:
        print("유효한 PE 파일이 아닙니다.")
    except Exception as e:
        print(f"에러 발생: {e}")

# 해시값 확인
def get_file_hashes(file_path):
    try:
        hashes = {"MD5": hashlib.md5(), "SHA1": hashlib.sha1(), "SHA256": hashlib.sha256()}
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                for algo in hashes.values():
                    algo.update(chunk)

        print("\n🔍 [파일 해시값]")
        for name, algo in hashes.items():
            print(f"  {name}: {algo.hexdigest()}")
        
        return {name: algo.hexdigest() for name, algo in hashes.items()}  # 해시값 반환

    except FileNotFoundError:
        print("파일을 찾을 수 없습니다. 파일 경로를 확인하세요.")
    except Exception as e:
        print(f"에러 발생: {e}")

# PE 헤더 확인 
def check_signature(file_path):
    try:
        with open(file_path, "rb") as f:
            mz_signature = f.read(2)
            if mz_signature != b'MZ':
                print("유효한 MZ(Signature) 헤더가 아닙니다.")
                return
            
            f.seek(0x3C)  
            pe_offset = struct.unpack("<I", f.read(4))[0]
            f.seek(pe_offset)
            pe_signature = f.read(4)
            if pe_signature != b'PE\x00\x00':
                print("유효한 PE(Signature) 헤더가 아닙니다.")
                return
            
            print(f"✅ MZ Signature 확인됨! (0x{mz_signature.hex().upper()})")
            print(f"✅ PE Signature 확인됨! (0x{pe_signature.hex().upper()}) at offset 0x{pe_offset:X}")
    
    except FileNotFoundError:
        print("파일을 찾을 수 없습니다. 파일 경로를 확인하세요.")
    except Exception as e:
        print(f"에러 발생: {e}")
        
# DLL 목록 확인
def get_imported_libraries(file_path):
    try:
        pe = pefile.PE(file_path)
        print("\n🔍 [Import된 라이브러리(DLL) 및 함수 목록]")

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode()
                print(f"📂 {dll_name}")
                
                for imp in entry.imports:
                    func_name = imp.name.decode() if imp.name else "Ordinal_" + str(imp.ordinal)
                    if func_name in suspicious_apis:
                        print(f"    └ 🚨 {func_name} (의심됨)")
                    else:
                        print(f"    └ {func_name}")
        else:
            print("⚠️ Import Table이 없습니다. (패킹되었을 가능성 있음)")
    
    except pefile.PEFormatError:
        print("유효한 PE 파일이 아닙니다.")
    except Exception as e:
        print(f"에러 발생: {e}")

def analyze_pe(file_path):
    get_file_type(file_path)
    unpacked_path = check_packing(file_path) or file_path  # 언패킹된 파일 사용
    get_file_hashes(file_path)
    check_signature(unpacked_path)
    get_imported_libraries(unpacked_path)
