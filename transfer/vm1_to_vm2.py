#!/usr/bin/env python3
import paramiko
import yaml
import argparse
import os
import sys

def load_config(config_file="config.yaml"):
    """
    YAML 형식의 설정 파일을 읽어 딕셔너리로 반환합니다.
    """
    try:
        with open(config_file, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"설정 파일 '{config_file}' 로드 중 오류 발생: {e}", file=sys.stderr)
        sys.exit(1)

def sftp_transfer_vm1_to_vm2(config_section, local_file):
    """
    config_section에 정의된 정보를 사용하여 VM1 → VM2 SFTP 연결을 생성한 후,
    local_file을 원격 서버의 지정된 경로로 전송합니다.
    """
    host = config_section.get("host")
    port = config_section.get("port", 22)
    username = config_section.get("username")
    password = config_section.get("password")
    remote_path = config_section.get("remote_path")

    if not all([host, username, password, remote_path]):
        print("필요한 SFTP 설정값이 누락되었습니다.", file=sys.stderr)
        sys.exit(1)

    # Paramiko의 SSHClient를 사용하여 SSH 연결을 생성하고 SFTP 세션을 엽니다.
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=port, username=username, password=password)
    except Exception as e:
        print(f"{host}:{port}에 연결하는 중 오류 발생: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        sftp = ssh.open_sftp()
        filename = os.path.basename(local_file)
        # remote_path가 디렉터리라면 파일명을 결합하여 최종 원격 파일 경로 생성
        remote_file = os.path.join(remote_path, filename)
        sftp.put(local_file, remote_file)
        print(f"'{local_file}' 파일을 {host}:{remote_file} 로 성공적으로 전송하였습니다.")
        sftp.close()
    except Exception as e:
        print(f"SFTP 전송 중 오류 발생: {e}", file=sys.stderr)
    finally:
        ssh.close()

def main():
    parser = argparse.ArgumentParser(
        description="VM1 → VM2 전송 설정을 이용한 SFTP 파일 전송 (config.yaml의 vm1_to_vm2 섹션 사용)"
    )
    parser.add_argument("local_file", help="전송할 로컬 파일 경로")
    parser.add_argument("--config", default="config.yaml", help="설정 파일 경로 (기본값: config.yaml)")
    args = parser.parse_args()

    config = load_config(args.config)
    vm1_to_vm2_config = config.get("vm1_to_vm2")
    if not vm1_to_vm2_config:
        print("설정 파일에 'vm1_to_vm2' 섹션이 없습니다.", file=sys.stderr)
        sys.exit(1)

    sftp_transfer_vm1_to_vm2(vm1_to_vm2_config, args.local_file)

if __name__ == "__main__":
    main()
