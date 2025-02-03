"""
transfer_back_results.py
------------------------
원격 VM에서 파일을 호스트로 SFTP를 통해 가져오는 스크립트입니다.

사용법:
    python3 transfer_back_results.py --host <VM_HOST> --port <SSH_PORT> \
       --username <USERNAME> --password <PASSWORD> \
       --remote-path <REMOTE_FILE> --local-path <LOCAL_FILE>

예시:
    python3 transfer_back_results.py --host 192.168.56.101 --username vuser --password vpass \
       --remote-path /C:/analysis/dynamic_analysis.json --local-path /home/user/dynamic_analysis.json
"""

import paramiko
import argparse
import sys
import os

def transfer_file_from_vm(host, port, username, password, remote_path, local_path):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sftp = None
    try:
        ssh.connect(hostname=host, port=port, username=username, password=password)
        sftp = ssh.open_sftp()
        sftp.get(remote_path, local_path)
        print(f"[+] Successfully transferred '{host}:{remote_path}' to {local_path}")
    finally:
        if sftp is not None:
            sftp.close()
        ssh.close()

def main():
    parser = argparse.ArgumentParser(description="Transfer file from VM to host via SFTP.")
    parser.add_argument("--host", required=True, help="VM IP or hostname")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", required=True, help="SSH password")
    parser.add_argument("--remote-path", required=True, help="Path on VM of the file to download")
    parser.add_argument("--local-path", required=True, help="Local path where the file will be saved")
    args = parser.parse_args()

    try:
        transfer_file_from_vm(
            host=args.host,
            port=args.port,
            username=args.username,
            password=args.password,
            remote_path=args.remote_path,
            local_path=args.local_path
        )
    except Exception as e:
        print(f"[-] Error during file download: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
