import os
import sys
import argparse
import logging
import yaml
import paramiko
from file_transfer import SSHConfig, sftp_transfer

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
    Host PC에서 파일을 VM1으로 전송하고, VM1에 저장된 파일 경로를 반환합니다.
    """
    vm1_cfg = config["host_to_vm1"]
    vm1_config = SSHConfig(
        host=vm1_cfg["host"],
        port=vm1_cfg["port"],
        username=vm1_cfg["username"],
        password=vm1_cfg["password"]
    )
    remote_file_path = os.path.join(vm1_cfg["remote_path"], os.path.basename(file_path))
    sftp_transfer(vm1_config, file_path, remote_file_path)
    return remote_file_path

def ensure_remote_directory(vm1_config: SSHConfig, remote_dir: str):
    """
    VM1에 SSH로 접속하여, remote_dir 디렉토리가 없으면 생성합니다.
    """
    command = f"mkdir -p {remote_dir}"
    logging.info(f"Ensuring remote directory exists: {remote_dir}")
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
        stdout.channel.recv_exit_status()  # 명령어 종료까지 대기
        logging.info("Remote directory ensured.")
    except Exception as e:
        logging.error(f"Error ensuring remote directory: {e}")
        raise
    finally:
        client.close()

def upload_file_to_vm1(local_path: str, remote_path: str, vm1_config: SSHConfig):
    """
    Host PC에서 VM1으로 파일을 업로드합니다.
    """
    sftp_transfer(vm1_config, local_path, remote_path)

def execute_remote_command(vm1_config: SSHConfig, command: str):
    """
    VM1에 SSH로 접속하여 원격 명령을 실행합니다.
    """
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
        output = stdout.read().decode("utf-8").strip()
        errors = stderr.read().decode("utf-8").strip()
        logging.info("Remote command output: " + output)
        if errors:
            logging.error("Remote command errors: " + errors)
        else:
            logging.info("Remote command executed successfully.")
    except Exception as e:
        logging.error(f"Error executing remote command on VM1: {e}")
    finally:
        client.close()

def main():
    parser = argparse.ArgumentParser(
        description="Host PC: Transfer file to VM1 and instruct VM1 to transfer file to VM2."
    )
    parser.add_argument(
        "--file",
        required=True,
        help="전송할 파일 경로 (예: 'D:/path/to/your/file.json')"
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="설정 파일 경로 (default: config.yaml)"
    )
    parser.add_argument(
        "--script",
        default="vm1_to_vm2.py",
        help="Host PC에 있는 VM1용 스크립트 파일 경로 (예: 'vm1_to_vm2.py'). 수정 필요 시 변경"
    )
    parser.add_argument(
        "--file_transfer",
        default="file_transfer.py",
        help="Host PC에 있는 SFTP 전송 모듈 파일 경로 (예: 'file_transfer.py'). 수정 필요 시 변경"
    )
    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except Exception as e:
        logging.error(f"Error loading config: {e}")
        sys.exit(1)

    file_path = args.file

    # 1. Host PC에서 VM1으로 파일 전송 (메인 파일)
    logging.info("Transferring main file from Host PC to VM1...")
    remote_file_path = host_to_vm1(file_path, config)
    logging.info(f"Main file transferred to VM1 at: {remote_file_path}")

    # 2. VM1의 임시 디렉토리 확인 및 생성 (config에 vm1_temp_dir이 지정되어 있으면 사용)
    vm1_cfg = config["host_to_vm1"]
    vm1_config = SSHConfig(
        host=vm1_cfg["host"],
        port=vm1_cfg["port"],
        username=vm1_cfg["username"],
        password=vm1_cfg["password"]
    )
    vm1_temp_dir = config.get("vm1_temp_dir", f"/home/{vm1_cfg['username']}/temporary/")
    ensure_remote_directory(vm1_config, vm1_temp_dir)

    # 3. Host PC에서 VM1으로 vm1_to_vm2.py, config.yaml, file_transfer.py 업로드
    remote_script_path = os.path.join(vm1_temp_dir, os.path.basename(args.script))
    remote_config_path = os.path.join(vm1_temp_dir, os.path.basename(args.config))
    remote_file_transfer_path = os.path.join(vm1_temp_dir, os.path.basename(args.file_transfer))
    
    logging.info("Uploading vm1_to_vm2.py to VM1: " + remote_script_path)
    upload_file_to_vm1(args.script, remote_script_path, vm1_config)
    logging.info("Uploading config.yaml to VM1: " + remote_config_path)
    upload_file_to_vm1(args.config, remote_config_path, vm1_config)
    logging.info("Uploading file_transfer.py to VM1: " + remote_file_transfer_path)
    upload_file_to_vm1(args.file_transfer, remote_file_transfer_path, vm1_config)

    # 4. Host PC에서 VM1에 원격 명령 실행: 업로드한 vm1_to_vm2.py를 실행하여 VM1 → VM2 전송
    command = f"python3 {remote_script_path} --file {remote_file_path} --config {remote_config_path}"
    execute_remote_command(vm1_config, command)

    # 5. (선택사항) 임시 업로드 파일 정리: 필요 시 VM1에서 임시 파일들을 삭제하는 명령을 추가할 수 있습니다.

if __name__ == "__main__":
    main()
