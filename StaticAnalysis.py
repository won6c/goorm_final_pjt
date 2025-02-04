import magic
import hashlib
import pefile

file_path=r"c:/"

def get_file_type(file_path):

    return magic.from_buffer(file_path,mime=True)

def get_file_hash_sha256(file_path,hash_type):
    hash_type = hash_type.lower()
    
    if hash_type not in ("md5", "sha1", "sha256"):
        raise ValueError(f"Unsupported hash type: {hash_type}")
    
    hasher = getattr(hashlib, hash_type)()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    
    file_hash = hasher.hexdigest()

    return file_hash

def check_if_packed(file_path):
    pe = pefile.PE(file_path)

    packed_signatures = ["UPX", "MPRESS", "ASPACK", " Themida", "EXE Stealth", "MEW"]  # 예시
    detected = []

    for section in pe.sections:
        section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        for sig in packed_signatures:
            if sig.upper() in section_name.upper():
                detected.append((section_name, sig))

        entropy = section.get_entropy()
        if entropy > 7.5:
            detected.append((section_name, f"High entropy: {entropy:.2f}"))

    pe.close()
    return detected

