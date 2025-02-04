# main.py
import os
import sys
import argparse
import logging
import yaml
from file_transfer import SSHConfig, sftp_transfer
import paramiko

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def load_config(config_file: str):
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Config file not found: {config_file}")
    with open(config_file, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    if config is None:
        raise ValueError(f"Config file {config_file} is empty or invalid.")
    logging.info(f"Config loaded: {config}")
    return config

def host_to_vm1(file_path: str, config: dict) -> str:
    """
    Host PC에서 파일을 VM1으로 전송합니다.
    전송 후, VM1의 저장 경로를 반환합니다.
    """
    vm1_cfg = config["host_to_vm1"]
    vm1_config = SSHConfig(
        host=vm1_cfg["host"],
        port=vm1_cfg["port"],
        username=vm1_cfg["username"],
        password=vm1_cfg["password"]
    )
    remote_path = os.path.join(vm1_cfg["remote_path"], os.path.basename(file_path))
    sftp_transfer(vm1_config, file_path, remote_path)
    return remote_path

def vm1_send_to_elk_remote(remote_file_path: str, config: dict):
    """
    VM1에 원격으로 접속하여, 미리 설치된 elk_sender.py 스크립트를 실행시켜
    해당 JSON 파일을 AWS ELK로 전송합니다.
    이 함수는 VM1에서 elk_sender.py가 /home/pyh/elk_sender.py 경로에 존재한다고 가정합니다.
    """
    vm1_cfg = config["host_to_vm1"]
    vm1_config = SSHConfig(
        host=vm1_cfg["host"],
        port=vm1_cfg["port"],
        username=vm1_cfg["username"],
        password=vm1_cfg["password"]
    )
    # 원격 명령: VM1에서 elk_sender.py 스크립트를 실행하여 파일을 전송합니다.
    # 예: python3 /home/pyh/elk_sender.py --file /home/pyh/Desktop/analysis_test.json
    command = f"python3 /home/pyh/elk_sender.py --file {remote_file_path}"
    logging.info(f"Executing remote command on VM1: {command}")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=vm1_config.host,
            port=vm1_config.port,
            username=vm1_config.username,
            password=vm1_config.password
        )
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode('utf-8')
        errors = stderr.read().decode('utf-8')
        logging.info("Remote command output: " + output)
        if errors:
            logging.error("Remote command errors: " + errors)
    except Exception as e:
        logging.error(f"Error executing remote command on VM1: {e}")
    finally:
        client.close()

def main():
    parser = argparse.ArgumentParser(
        description="Host PC: Transfer file to VM1 and instruct VM1 to send JSON to AWS ELK"
    )
    # 여기서 --file 인자는 Windows 경로를 사용 (백슬래시 문제를 피하기 위해 슬래시 사용)
    parser.add_argument(
        "--file",
        required=True,
        help="전송할 파일 경로 (예: 'D:/goorm/FinalProject/goorm_final_pjt/transfer_test/analysis_test.json')"
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

    # 1. Host PC에서 VM1으로 파일 전송
    logging.info("Transferring file from Host PC to VM1...")
    remote_file_path = host_to_vm1(file_path, config)
    logging.info(f"File transferred to VM1 at: {remote_file_path}")

    # 2. VM1에서 원격 명령 실행을 통해 AWS ELK로 전송하도록 지시
    logging.info("Instructing VM1 to send the file to AWS ELK...")
    vm1_send_to_elk_remote(remote_file_path, config)

if __name__ == "__main__":
    main()
