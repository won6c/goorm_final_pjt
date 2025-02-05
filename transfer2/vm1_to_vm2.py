# vm1_to_vm2.py
import os
import argparse
import logging
import yaml
from file_transfer import SSHConfig, sftp_transfer

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def load_config(config_file: str):
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Config file not found: {config_file}")
    with open(config_file, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    if config is None:
        raise ValueError(f"Config file {config_file} is empty or invalid.")
    return config

def vm1_to_vm2(file_path: str, config: dict):
    """
    VM1에서 file_path의 파일을 VM2로 전송합니다.
    """
    vm2_cfg = config["vm1_to_vm2"]
    vm2_config = SSHConfig(
        host=vm2_cfg["host"],
        port=vm2_cfg["port"],
        username=vm2_cfg["username"],
        password=vm2_cfg["password"]
    )
    remote_path = os.path.join(vm2_cfg["remote_path"], os.path.basename(file_path))
    sftp_transfer(vm2_config, file_path, remote_path)
    logging.info(f"File transferred from VM1 to VM2 at: {remote_path}")

def main():
    parser = argparse.ArgumentParser(description="Transfer file from VM1 to VM2.")
    parser.add_argument("--file", required=True, help="File path on VM1 to transfer to VM2")
    parser.add_argument("--config", default="config.yaml", help="Configuration file path")
    args = parser.parse_args()
    config = load_config(args.config)
    vm1_to_vm2(args.file, config)

if __name__ == "__main__":
    main()
