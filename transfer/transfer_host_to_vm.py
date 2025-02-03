#!/usr/bin/env python3
"""
transfer_to_ubuntu.py
---------------------
호스트 PC의 파일을 Guest Ubuntu로 SFTP를 통해 전송하는 스크립트입니다.

사용법:
    python3 transfer_to_ubuntu.py --host <GUEST_UBUNTU_IP> --port <SSH_PORT> \
       --username <USERNAME> --password <PASSWORD> \
       --local-path <LOCAL_FILE_PATH> --remote-path <REMOTE_FILE_PATH>

예시:
    python3 transfer_to_ubuntu.py --host 192.168.56.101 --port 22 \
       --username ubuntu --password myubuntupass \
       --local-path /home/user/malware.exe --remote-path /home/ubuntu/malware.exe
"""

import paramiko
import argparse
import sys
import os

def transfer_file_to_vm(host, port, username, password, local_path, remote_path):
    if not os.path.exists(local_path):
        raise FileNotFoundError(f"Local file not found: {local_path}")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sftp = None
    try:
        ssh.connect(hostname=host, port=port, username=username, password=password)
        sftp = ssh.open_sftp()
        sftp.put(local_path, remote_path)
        print(f"[+] Successfully transferred '{local_path}' to {host}:{remote_path}")
    finally:
        if sftp is not None:
            sftp.close()
        ssh.close()

def main():
    parser = argparse.ArgumentParser(description="Transfer file from host PC to Guest Ubuntu via SFTP.")
    parser.add_argument("--host", required=True, help="Guest Ubuntu IP or hostname")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", required=True, help="SSH password")
    parser.add_argument("--local-path", required=True, help="Local file path on host PC")
    parser.add_argument("--remote-path", required=True, help="Destination file path on Guest Ubuntu")
    args = parser.parse_args()

    try:
        transfer_file_to_vm(args.host, args.port, args.username, args.password, args.local_path, args.remote-path)
    except Exception as e:
        print(f"[-] Error during file transfer: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
