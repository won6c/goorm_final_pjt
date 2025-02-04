# file_transfer.py
import os
import logging
import paramiko

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class SSHConfig:
    def __init__(self, host, port, username, password):
        self.host = host
        self.port = port
        self.username = username
        self.password = str(password)  # 반드시 문자열로 처리

def sftp_transfer(ssh_config: SSHConfig, local_path: str, remote_path: str):
    """
    Paramiko를 이용하여 local_path의 파일을 원격 서버(ssh_config)의 remote_path로 전송합니다.
    """
    if not os.path.exists(local_path):
        raise FileNotFoundError(f"Local file not found: {local_path}")

    logging.info(f"Connecting to {ssh_config.host}:{ssh_config.port} as {ssh_config.username}")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sftp = None
    try:
        client.connect(
            hostname=ssh_config.host,
            port=ssh_config.port,
            username=ssh_config.username,
            password=ssh_config.password
        )
        sftp = client.open_sftp()
        sftp.put(local_path, remote_path)
        logging.info(f"Successfully transferred '{local_path}' to {ssh_config.host}:{remote_path}")
    except Exception as e:
        logging.error(f"Error during file transfer: {e}")
        raise
    finally:
        if sftp:
            sftp.close()
            logging.debug("SFTP session closed.")
        client.close()
        logging.debug("SSH connection closed.")
