#!/usr/bin/env python3
import os
import sys
import argparse
import logging
import yaml
import paramiko
from file_transfer import SSHConfig, sftp_transfer

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def load_config(config_file: str):
    """
    config.yaml 로드
    """
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Config file not found: {config_file}")
    with open(config_file, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    if config is None:
        raise ValueError(f"Config file {config_file} is empty or invalid.")
    logging.info(f"Config loaded: {config}")
    return config

def ensure_vm1_dependencies(vm1_config: SSHConfig):
    """
    VM1에서 Python 3.10 및 필요한 라이브러리(cffi, paramiko, cryptography) 설치 여부 검사.
    없으면 자동 설치.
    """
    # 1) _cffi_backend 모듈이 있는지 python3.10로 확인
    check_command = "python3.10 -c 'import _cffi_backend'"
    
    # 설치 명령어 (sudo 비밀번호 사용)
    install_command = (
        f"echo {vm1_config.password} | sudo -S apt-get update -y && "
        f"echo {vm1_config.password} | sudo -S apt-get install -y python3.10 python3.10-dev python3.10-distutils "
        "python3-pip python3-cffi && "
        "python3.10 -m pip install --upgrade pip paramiko cryptography cffi"
    )

    logging.info("Checking VM1 for required Python dependencies with python3.10...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=vm1_config.host,
            port=vm1_config.port,
            username=vm1_config.username,
            password=vm1_config.password
        )
        stdin, stdout, stderr = client.exec_command(check_command)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            logging.info("Required Python dependencies (for python3.10) already installed on VM1.")
        else:
            logging.info("Dependencies not found. Installing dependencies on VM1 (python3.10)...")
            stdin2, stdout2, stderr2 = client.exec_command(install_command)
            stdout2.channel.recv_exit_status()  # 설치 완료 대기
            install_output = stdout2.read().decode("utf-8").strip()
            install_errors = stderr2.read().decode("utf-8").strip()
            logging.info("Dependencies installation output: " + install_output)
            if install_errors:
                logging.error("Dependencies installation errors: " + install_errors)
            else:
                logging.info("Dependencies installation completed successfully.")
    except Exception as e:
        logging.error(f"Error checking/installing dependencies on VM1: {e}")
        raise
    finally:
        client.close()

def host_to_vm1(file_path: str, config: dict) -> str:
    """
    Host → VM1로 file_path 전송. 
    반환값: VM1에 저장된 파일 경로
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
    VM1에서 remote_dir 디렉토리 없으면 생성
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
        stdout.channel.recv_exit_status()
        logging.info("Remote directory ensured: " + remote_dir)
    except Exception as e:
        logging.error(f"Error ensuring remote directory: {e}")
        raise
    finally:
        client.close()

def upload_file_to_vm1(local_path: str, remote_path: str, vm1_config: SSHConfig):
    """
    Host → VM1 파일 업로드
    """
    sftp_transfer(vm1_config, local_path, remote_path)

def execute_remote_command(vm1_config: SSHConfig, command: str):
    """
    VM1에서 원격 명령 실행 (python3.10 ... 사용)
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
        description="Host→VM1→VM2 or ELK automation with Python3.10 auto dependencies installation."
    )
    parser.add_argument(
        "--file",
        required=True,
        help="전송할 파일 경로 (예: 'D:/path/to/file.json' or 'file.exe')"
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="설정 파일 (default: config.yaml)"
    )
    parser.add_argument(
        "--mode",
        choices=["transfer", "elk"],
        default="transfer",
        help="transfer=VM1→VM2, elk=VM1→ELK. (기본=transfer)"
    )
    parser.add_argument(
        "--script",
        default="vm1_to_vm2.py",
        help="transfer 모드용: vm1_to_vm2.py, elk 모드: elk_sender.py"
    )
    parser.add_argument(
        "--file_transfer",
        default="file_transfer.py",
        help="기본=file_transfer.py"
    )
    args = parser.parse_args()

    # 1) config.yaml 로드
    try:
        config = load_config(args.config)
    except Exception as e:
        logging.error(f"Error loading config: {e}")
        sys.exit(1)

    # 2) VM1 SSHConfig
    vm1_cfg = config["host_to_vm1"]
    vm1_config = SSHConfig(
        host=vm1_cfg["host"],
        port=vm1_cfg["port"],
        username=vm1_cfg["username"],
        password=vm1_cfg["password"]
    )

    # 3) 항상 VM1 의존성 검사/설치
    try:
        ensure_vm1_dependencies(vm1_config)
    except Exception as e:
        logging.error(f"Dependency installation failed: {e}")
        sys.exit(1)

    # 4) Host → VM1 main 파일 전송
    logging.info("Transferring main file from Host PC to VM1...")
    remote_file_path = host_to_vm1(args.file, config)
    logging.info(f"Main file transferred to VM1 at: {remote_file_path}")

    # 5) VM1 임시 디렉토리 확인 생성
    vm1_temp_dir = config.get("vm1_temp_dir", f"/home/{vm1_cfg['username']}/temporary/")
    ensure_remote_directory(vm1_config, vm1_temp_dir)

    # 6) mode: transfer vs elk
    if args.mode == "elk":
        local_script = "elk_sender.py"
        remote_script_path = os.path.join(vm1_temp_dir, "elk_sender.py")
    else:
        local_script = args.script
        remote_script_path = os.path.join(vm1_temp_dir, os.path.basename(args.script))

    remote_config_path = os.path.join(vm1_temp_dir, os.path.basename(args.config))
    remote_file_transfer_path = os.path.join(vm1_temp_dir, os.path.basename(args.file_transfer))

    # 업로드
    logging.info(f"Uploading script to VM1: {remote_script_path}")
    upload_file_to_vm1(local_script, remote_script_path, vm1_config)
    logging.info(f"Uploading config to VM1: {remote_config_path}")
    upload_file_to_vm1(args.config, remote_config_path, vm1_config)
    logging.info(f"Uploading file_transfer.py to VM1: {remote_file_transfer_path}")
    upload_file_to_vm1(args.file_transfer, remote_file_transfer_path, vm1_config)

    # 7) python3.10으로 원격 스크립트 실행
    command = f"python3.10 {remote_script_path} --file {remote_file_path} --config {remote_config_path}"
    execute_remote_command(vm1_config, command)

if __name__ == "__main__":
    main()
