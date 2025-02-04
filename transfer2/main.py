# main.py
import os
import sys
import argparse
import logging
import yaml

from file_transfer import SSHConfig, sftp_transfer
from elk_sender import send_json_to_elk

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def load_config(config_file: str):
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Config file not found: {config_file}")
    with open(config_file, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

# 역할별 전송 기능
def host_to_vm1(file_path: str, config: dict):
    """
    Host PC에서 파일 A(악성코드 샘플)를 Guest VM1(우분투)로 전송
    """
    vm1_cfg = config["host_to_vm1"]
    vm1_config = SSHConfig(
        host=vm1_cfg["host"],
        port=vm1_cfg["port"],
        username=vm1_cfg["username"],
        password=vm1_cfg["password"]
    )
    # remote_path는 설정된 디렉토리에 파일 이름을 추가
    remote_path = os.path.join(vm1_cfg["remote_path"], os.path.basename(file_path))
    sftp_transfer(vm1_config, file_path, remote_path)

def vm1_to_vm2(file_path: str, config: dict):
    """
    Guest VM1(우분투)에서 파일 A를 Guest VM2(윈도우)로 전송
    """
    vm2_cfg = config["vm1_to_vm2"]
    vm2_config = SSHConfig(
        host=vm2_cfg["host"],
        port=vm2_cfg["port"],
        username=vm2_cfg["username"],
        password=vm2_cfg["password"]
    )
    # Windows 경로는 보통 슬래시(/) 사용 시에도 동작하거나, 별도 경로 구분자 사용
    remote_path = os.path.join(vm2_cfg["remote_path"], os.path.basename(file_path))
    sftp_transfer(vm2_config, file_path, remote_path)

def vm2_to_vm1(json_path: str, config: dict):
    """
    Guest VM2(윈도우)에서 분석 보고서(JSON)를 Guest VM1(우분투)로 전송
    """
    vm1_cfg = config["vm2_to_vm1"]
    vm1_config = SSHConfig(
        host=vm1_cfg["host"],
        port=vm1_cfg["port"],
        username=vm1_cfg["username"],
        password=vm1_cfg["password"]
    )
    remote_path = os.path.join(vm1_cfg["remote_path"], os.path.basename(json_path))
    sftp_transfer(vm1_config, json_path, remote_path)

def vm1_send_to_elk(json_path: str, config: dict):
    """
    Guest VM1에서 분석 보고서(JSON)를 AWS ELK로 전송
    """
    elk_cfg = config["elk"]
    endpoint = elk_cfg["endpoint"]
    headers = elk_cfg.get("headers")
    send_json_to_elk(json_path, endpoint, headers)

def main():
    parser = argparse.ArgumentParser(
        description="Malware Analysis Automation: Multi-hop File Transfer & Analysis Report Processing using config file."
    )
    parser.add_argument(
        "--role",
        choices=["host", "vm1", "vm2"],
        required=True,
        help="현재 머신의 역할: host (Host PC), vm1 (Guest Ubuntu), vm2 (Guest Windows)"
    )
    parser.add_argument(
        "--file",
        required=True,
        help="전송할 파일 경로 (악성코드 샘플 또는 분석 보고서 JSON 파일)"
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="설정 파일 경로 (default: config.yaml)"
    )
    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except Exception as e:
        logging.error(f"Error loading config: {e}")
        sys.exit(1)

    file_path = args.file

    if args.role == "host":
        logging.info("Role: host → Host PC에서 Guest VM1으로 파일 전송")
        host_to_vm1(file_path, config)
    elif args.role == "vm1":
        # vm1에서는 파일 A라면 vm1→vm2 전송, JSON 파일이면 AWS ELK 전송
        if file_path.lower().endswith(".json"):
            logging.info("Role: vm1 → 분석 보고서(JSON)를 AWS ELK로 전송")
            vm1_send_to_elk(file_path, config)
        else:
            logging.info("Role: vm1 → 파일 A를 Guest VM2로 전송")
            vm1_to_vm2(file_path, config)
    elif args.role == "vm2":
        logging.info("Role: vm2 → 분석 보고서(JSON)를 Guest VM1으로 전송")
        vm2_to_vm1(file_path, config)
    else:
        logging.error("Invalid role specified.")
        sys.exit(1)

if __name__ == "__main__":
    main()
