import winreg
import json
from datetime import datetime


def capture_reg(root_key, key_name):
    capture_dict = {"values": {}, "subkeys": []}
    try:     
        registry_key = winreg.OpenKey(root_key, key_name, 0, winreg.KEY_READ)
        i = 0
        while True:
            try:
                with open("./capture.txt", "a", encoding="utf-8") as f:
                    f.write(f"{winreg.EnumValue(registry_key, i)}")
                    f.write("\n")

                value_name, value_data, value_type = winreg.EnumValue(registry_key, i)
                if isinstance(value_data, bytes):
                    value_data = value_data.decode("utf-8", errors="replace")
                capture_dict["values"][value_name] = value_data
                i += 1
            except OSError:
                break

        i = 0
        while True:
            try:
                sub_key_name = winreg.EnumKey(registry_key, i)
                capture_dict["subkeys"].append(sub_key_name) 
                full_subkey_path = f"{key_name}\\{sub_key_name}" if key_name else sub_key_name
                capture_dict[sub_key_name] = capture_reg(root_key, full_subkey_path)
                i += 1
            except OSError:
                break

        winreg.CloseKey(registry_key)
    except Exception as e:
        print(f"Error accessing {key_name}: {e}")
    return capture_dict


#def flatten_registry_data(data, parent_key=""):
#    flat_data = {}
#
#    for key, value in data.get("values", {}).items():
#        print(f"key:{key}, value:{value}")
#        input()
#        path = f"{parent_key}\\{key}" if parent_key else key
#        flat_data[path] = value
#    print(flat_data)
#    for subkey in data.get("subkeys", []):
#        subkey_path = f"{parent_key}\\{subkey}" if parent_key else subkey
#        flat_data.update(flatten_registry_data(data.get(subkey, {}), subkey_path))
#    print(flat_data)
#    return flat_data

def flatten_registry_data(data, parent_key=""):
    flat_data = {}
    
    if "HKEY_CURRENT_USER" in data.keys():
        data = data["HKEY_CURRENT_USER"]
    if "values" in data:
        for key, value in data["values"].items():
            path = f"{parent_key}\\{key}" if parent_key else key
            flat_data[path] = value
            
    if "subkeys" in data:
        for subkey in data["subkeys"]:
            subkey_path = f"{parent_key}\\{subkey}" if parent_key else subkey
            if subkey in data:
                flat_data.update(flatten_registry_data(data[subkey], subkey_path))
            else:
                flat_data[subkey_path] = {}
            
    return flat_data



def compare_registry_paths(capture1, capture2):
    added = {key: capture2[key] for key in capture2 if key not in capture1}
    deleted = {key: capture1[key] for key in capture1 if key not in capture2}
    modified = {
        key: {"old": capture1[key], "new": capture2[key]}
        for key in capture1
        if key in capture2 and capture1[key] != capture2[key]
    }

    return added, modified, deleted


def process():
    root_keys = [
        (winreg.HKEY_CURRENT_USER, "HKEY_CURRENT_USER"),
    ]

    capture_data = {}
    for root_key, key_name in root_keys:
        capture_data[key_name] = capture_reg(root_key, "")
    return capture_data


def main():
    print("Before execution...")
    before_capture = process()
    with open("./before_capture.json",'w') as f:
        json.dump(before_capture,f,indent=4)
    print("Waiting for changes... Press Enter to continue.")
    input("Pause")

    print("After execution...")
    after_capture = process()
    with open("./after_capture.json",'w') as f:
        json.dump(after_capture,f,indent=4)

    #with open("./before_capture.json", "r") as f:
    #    before_capture = json.load(f)
    #with open("./after_capture.json", "r") as f:
    #    after_capture = json.load(f)
    flat_before = flatten_registry_data(before_capture)

    flat_after = flatten_registry_data(after_capture)

    added, modified, deleted = compare_registry_paths(flat_before, flat_after)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result = {
        "timestamp": timestamp,
        "added": added,
        "modified": modified,
        "deleted": deleted,
    }

    print("Changes detected:")
    print(json.dumps(result, indent=4, ensure_ascii=False))

    with open("registry_changes.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4, ensure_ascii=False)


if __name__ == "__main__":
    main()
