#!/usr/bin/env python3
import os
import sys
import argparse
import logging
import yaml
import paramiko
from file_transfer import SSHConfig, sftp_transfer

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# 기본적으로 사용할 파이썬 인터프리터 명령어를 "python3"로 지정합니다.
PYTHON_INTERPRETER = "python3"

def load_config(config_file: str):
    """Load configuration from a YAML file."""
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Config file not found: {config_file}")
    with open(config_file, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    if config is None:
        raise ValueError(f"Config file {config_file} is empty or invalid.")
    return config

def ensure_vm1_dependencies(vm1_config, python_interpreter: str):
    """
    On VM1, check if the specified python interpreter with needed libraries (_cffi_backend, yaml, etc.) is installed.
    If not, install them using apt-get and pip.
    """
    check_command = f"{python_interpreter} -c 'import _cffi_backend, yaml'"
    install_command = (
        f"echo {vm1_config.password} | sudo -S apt-get update -y && "
        f"echo {vm1_config.password} | sudo -S apt-get install -y python3-pip python3-cffi && "
        f"{python_interpreter} -m pip install --upgrade pip paramiko cryptography cffi pyyaml"
    )

    logging.info(f"Checking VM1 for required Python dependencies using {python_interpreter}...")
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
            logging.info("Required Python dependencies are already installed on VM1.")
        else:
            logging.info("Dependencies not found. Installing on VM1...")
            stdin2, stdout2, stderr2 = client.exec_command(install_command)
            stdout2.channel.recv_exit_status()
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
    Transfer a local file from Host PC to VM1, returning the remote file path.
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

def ensure_remote_directory(vm1_config, remote_dir: str):
    """
    Ensure the specified directory exists on VM1.
    """
    command = f"mkdir -p {remote_dir}"
    logging.info(f"Ensuring remote directory exists on VM1: {remote_dir}")
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
        logging.error(f"Error ensuring remote directory on VM1: {e}")
        raise
    finally:
        client.close()

def upload_file_to_vm1(local_path: str, remote_path: str, vm1_config: SSHConfig):
    """
    Upload a file from Host to VM1 using SFTP.
    """
    sftp_transfer(vm1_config, local_path, remote_path)

def execute_remote_command(vm1_config, command: str, python_interpreter: str):
    """
    Execute the given command on VM1 using the specified python interpreter.
    """
    full_command = f"{python_interpreter} {command}"
    logging.info(f"Executing remote command on VM1: {full_command}")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=vm1_config.host,
            port=vm1_config.port,
            username=vm1_config.username,
            password=vm1_config.password
        )
        stdin, stdout, stderr = client.exec_command(full_command)
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
        description="Host → VM1 file transfer + upload scripts + run vm1_to_vm2.py on VM1"
    )
    parser.add_argument("--file", required=True, help="File path on Host PC to send to VM1")
    parser.add_argument("--config", default="config.yaml", help="Path to the configuration file (default: config.yaml)")
    parser.add_argument("--script", default="vm1_to_vm2.py", help="Path to vm1_to_vm2.py on Host PC (for VM1→VM2 execution)")
    parser.add_argument("--elk_sender", default="elk_sender.py", help="Path to elk_sender.py on Host PC (to be uploaded to VM1)")
    parser.add_argument("--file_transfer", default="file_transfer.py", help="Path to file_transfer.py on Host PC")
    args = parser.parse_args()

    # 1) Load config
    try:
        config = load_config(args.config)
    except Exception as e:
        logging.error(f"Error loading config: {e}")
        sys.exit(1)

    # 2) Prepare VM1 SSH config
    vm1_cfg = config["host_to_vm1"]
    vm1_config = SSHConfig(
        host=vm1_cfg["host"],
        port=vm1_cfg["port"],
        username=vm1_cfg["username"],
        password=vm1_cfg["password"]
    )

    # 3) Check/install dependencies on VM1 using the default python interpreter
    try:
        ensure_vm1_dependencies(vm1_config, PYTHON_INTERPRETER)
    except Exception as e:
        logging.error(f"Dependency installation failed: {e}")
        sys.exit(1)

    # 4) Transfer main file from Host → VM1
    logging.info("Transferring main file from Host to VM1...")
    remote_file_path = host_to_vm1(args.file, config)
    logging.info(f"Main file transferred to VM1 at: {remote_file_path}")

    # 5) Ensure VM1 temporary directory exists
    vm1_temp_dir = config.get("vm1_temp_dir", f"/home/{vm1_cfg['username']}/temporary/")
    ensure_remote_directory(vm1_config, vm1_temp_dir)

    # 6) Always upload vm1_to_vm2.py, elk_sender.py, file_transfer.py, config.yaml to VM1
    remote_script = os.path.join(vm1_temp_dir, os.path.basename(args.script))
    remote_elk_sender = os.path.join(vm1_temp_dir, os.path.basename(args.elk_sender))
    remote_config_path = os.path.join(vm1_temp_dir, os.path.basename(args.config))
    remote_file_transfer = os.path.join(vm1_temp_dir, os.path.basename(args.file_transfer))

    logging.info(f"Uploading vm1_to_vm2.py to {remote_script}")
    upload_file_to_vm1(args.script, remote_script, vm1_config)

    logging.info(f"Uploading elk_sender.py to {remote_elk_sender}")
    upload_file_to_vm1(args.elk_sender, remote_elk_sender, vm1_config)

    logging.info(f"Uploading config to {remote_config_path}")
    upload_file_to_vm1(args.config, remote_config_path, vm1_config)

    logging.info(f"Uploading file_transfer.py to {remote_file_transfer}")
    upload_file_to_vm1(args.file_transfer, remote_file_transfer, vm1_config)

    # 7) Run vm1_to_vm2.py on VM1 using the default python interpreter
    command = f"{remote_script} --file {remote_file_path} --config {remote_config_path}"
    execute_remote_command(vm1_config, command, PYTHON_INTERPRETER)

if __name__ == "__main__":
    main()
