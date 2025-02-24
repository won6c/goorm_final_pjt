# Malware Analysis Automation


# Usage Guide
## Overview
- **`main.py`** automates:
  1. Checking/installing Python 3.10 + `_cffi_backend` on **VM1** (via `sudo apt` + `pip`).
  2. Transferring a specified file from **Host PC** to **VM1**.
  3. Depending on mode:
     - **`transfer`** (default): Execute `vm1_to_vm2.py` on VM1 to forward file to **VM2**.
     - **`elk`**: Execute `elk_sender.py` on VM1 to send JSON to **AWS ELK** (Elasticsearch).

## Files
- `config.yaml`
- `file_transfer.py`
- `vm1_to_vm2.py`
- `elk_sender.py`
- `main.py`

## How to Run

1. **Transfer Mode** (default)  
   ```bash
   python main.py --file "D:/path/to/file"

2. **ELK Mode**
    ```bash
    python main.py --file "D:/path/to/report.json" --mode elk