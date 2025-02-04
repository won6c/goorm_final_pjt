"""
transfer_with_config.py
-----------------------
YAML 설정 파일(예: config.yaml)에 정의된 SSH 접속 정보와 경로를 사용하여
파일 전송(SFTP)을 수행합니다.

사용법:
    python transfer_with_config.py [--config config.yaml]

옵션:
    --config   사용할 설정 파일 경로 (기본값: config.yaml)
"""
import argparse
import sys
import os
import yaml
import paramiko

def parse_config(config_path):
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def transfer_file(ssh_config, transfer_config):
    local_path = transfer_config["local_path"]
    remote_path = transfer_config["remote_path"]

    if not os.path.exists(local_path):
        raise FileNotFoundError(f"Local file not found: {local_path}")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sftp = None
    try:
        ssh.connect(
            hostname=ssh_config["host"],
            port=ssh_config["port"],
            username=ssh_config["username"],
            password=ssh_config["password"]
        )
        sftp = ssh.open_sftp()
        sftp.put(local_path, remote_path)
        print(f"[+] Successfully transferred '{local_path}' to {ssh_config['host']}:{remote_path}")
    finally:
        if sftp:
            sftp.close()
        ssh.close()

def main():
    parser = argparse.ArgumentParser(description="Transfer file via SFTP using a YAML config file.")
    parser.add_argument("--config", default="config.yaml", help="Path to the YAML config file.")
    args = parser.parse_args()

    try:
        config = parse_config(args.config)

        # config.yaml에서 ssh 설정(ssh_config)과 파일 전송 설정(transfer_config) 가져오기
        ssh_config = config.get("ssh")
        transfer_config = config.get("transfer")

        if not ssh_config or not transfer_config:
            raise ValueError("Invalid config structure. 'ssh' or 'transfer' key is missing.")

        # 실제 파일 전송
        transfer_file(ssh_config, transfer_config)

    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
