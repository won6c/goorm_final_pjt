import os
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import torch
import torch.nn.functional as F
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import sys

###################################
# 1) 모든 섹션 디스어셈블 함수
###################################
def disassemble_all_sections(pe_file_path):
    """
    주어진 PE 파일(.exe)의 모든 섹션을 디스어셈블.
    모든 섹션에서 얻은 어셈블리 코드를 하나의 큰 문자열로 합쳐 반환.
    (데이터 섹션도 디스어셈블하므로 의미 없는 명령어가 다량 포함될 수 있음)
    """
    if not os.path.isfile(pe_file_path):
        return ""

    try:
        pe = pefile.PE(pe_file_path)
    except Exception as e:
        print(f"[!] PE 파싱 실패: {e}")
        return ""

    machine = pe.FILE_HEADER.Machine
    if machine == 0x8664:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif machine == 0x14c:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    else:
        print(f"[!] 지원하지 않는 머신 타입: 0x{machine:X}")
        return ""

    all_assembly_lines = []

    for section in pe.sections:
        section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        section_data = section.get_data()
        if not section_data:
            continue

        base_address = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
        lines_in_this_section = []

        for insn in md.disasm(section_data, base_address):
            line = f"0x{insn.address:X}: {insn.mnemonic} {insn.op_str}"
            lines_in_this_section.append(line)

        all_assembly_lines.append(f"; SECTION: {section_name}  VA=0x{base_address:X}")
        all_assembly_lines.extend(lines_in_this_section)

    asm_code = "\n".join(all_assembly_lines)
    return asm_code

###################################
# 2) 악성/정상 판별 함수
###################################
def classify_exe(
    exe_file_path, 
    tokenizer, 
    model, 
    max_length=256, 
    threshold=0.5
):
    """
    exe_file_path의 모든 섹션을 디스어셈블한 어셈블리 코드를 모델에 입력하여,
    악성 확률(softmax[1])을 계산하고 threshold를 기준으로 
    "악성" 또는 "정상"으로 판별하여 튜플 (악성확률, classification)를 반환.
    """
    asm_code = disassemble_all_sections(exe_file_path)
    if not asm_code:
        return None, "Unknown"

    inputs = tokenizer(
        asm_code,
        truncation=True,
        max_length=max_length,
        padding="max_length",
        return_tensors="pt"
    )

    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits

    probs = F.softmax(logits, dim=-1)
    malware_prob = probs[0, 1].item()  # index=0: 정상, index=1: 악성

    classification = "Malware" if malware_prob >= threshold else "Normal"
    return malware_prob, classification

###################################
# 3) 실행 예시
###################################
def process_llm():
    # 학습된 모델 경로
    model_path = os.path.join(os.getcwd(), "static_analysis", "codebert_asm_malware")
    # 검사할 exe 파일
    exe_file = sys.argv[1]

    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model = AutoModelForSequenceClassification.from_pretrained(model_path)
    model.eval()

    malware_prob, classification = classify_exe(exe_file, tokenizer, model)
    if malware_prob is None:
        return {"probability":"None","result":"None"}
    else:
        return {"probability":f"{malware_prob:.4f}","result":f"{classification}"}

