import os
import csv
import pefile

def extract_imports(file_path):
    # (이 부분은 동일. 파일에서 PE Imports 추출)
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        print(f"Error parsing {file_path}: {e}")
        return ""
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
    return " ".join(imports_list)

def main():
    csv_path = os.path.join(os.getcwd(), "malware_sample", "Malware_KIS", "KIS_label.csv")  # 내부에 filename, label 열이 있다고 가정
    # exe 파일들이 위치한 디렉터리 (만약 CSV에 절대 경로가 있으면 사용 안해도 됨)
    exe_folder = os.path.join(os.getcwd(), "malware_sample", "benign_dataset")

    # 출력 CSV (text,label) - 학습용
    output_csv = "train_data.csv"

    data_rows = []
    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            # row 예: [hash, year, filename.vir, label]
            # label= row[3], filename= row[2]
            if len(row) < 4:
                continue
            filename = row[0]  # e.g. "00011E3B80F7ED6...vir"
            label = row[3]     # "0" or "1"

            file_path = os.path.join(exe_folder, filename)
            if not os.path.isfile(file_path):
                print(f"File not found: {file_path}")
                continue

            imports_str = extract_imports(file_path)
            data_rows.append({"text": imports_str, "label": label})

    # write to train_data.csv
    with open(output_csv, "w", newline="", encoding="utf-8") as out_f:
        writer = csv.writer(out_f)
        writer.writerow(["text","label"])
        for dr in data_rows:
            writer.writerow([dr["text"], dr["label"]])
    
    print(f"Done! Processed {len(data_rows)} samples. Saved to {output_csv}")

if __name__ == "__main__":
    main()