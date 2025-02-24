import os
import subprocess
import logging

import paramiko
from requests import get

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def make_folder(path: str) -> str:
    if not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)
        logging.info(f'✅ Creating Directory: [{path}]')
    else:
        logging.info(f'⚠️ Directory is already existed: [{path}]')
    return path


def download_iso(iso_path: str, iso_url: str) -> None:
    if not os.path.isfile(iso_path):
        with open(iso_path, 'wb') as file:
            response = get(iso_url)
            if response.content:
                file.write(response.content)
                logging.info(f'✅ Downloading ISO_file: [{iso_path}]')
            else:
                logging.error(f'❌ Wronged ISO_url: [{iso_url}]')
    else:
        logging.warning(f'⚠️ ISO_file is already existed: [{iso_path}]')


def create_file(file_path: str, file_content: str) -> None:
    if not os.path.exists(file_path):
        logging.info(f'✅ Creating file: [{file_path}]')
        with open(file_path, 'w') as file:
            file.write(file_content)
    else:
        logging.warning(f'⚠️ file is already existed: [{file_path}]')


def cmd_run_admin(command: str) -> str:
    try:
        result = subprocess.run([
            'powershell',
            '-Command', 'Start-Process', 'cmd',
            '-ArgumentList', f'"/c {command}"',
            '-Verb', 'runAs', '-Wait'
            ],
            text=True, check=True
        )
        logging.info(f'✅ Command executed successfully: [{command}]')
    except subprocess.CalledProcessError as e:
        logging.error(f'❌ Error executing command: [{e}]')


class SSHClientManager:
    """Run command while connect SSH"""
    def __init__(self, hostname, username, password=None) -> None:
        self.hostname = hostname
        self.username = username
        self.password = password
        self.ssh = None  # SSHClient object

    def connect(self) -> None:
        """Setup SSH connection"""
        if not self.ssh:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            try:
                self.ssh.connect(hostname=self.hostname, username=self.username, password=self.password)
                logging.info(f'✅ Connect [{self.hostname}]')
            except paramiko.AuthenticationException:
                logging.error(f'❌ SSH Authentication failed')
                self.ssh = None
            except paramiko.SSHException as e:
                logging.error(f'❌ SSH Connection Error: [{e}]')
                self.ssh = None
            except Exception as e:
                logging.error(f'❌ Unexpected Error: [{e}]')
                self.ssh = None

    def execute_command(self, command: str) -> tuple[str | None, str | None]:
        """Run SSH command"""
        if not self.ssh:
            logging.error('❌ No SSH connection. Trying to reconnect...')
            self.connect()

        if self.ssh:
            try:
                stdin, stdout, stderr = self.ssh.exec_command(command)
                output = stdout.read().decode().strip()
                error = stderr.read().decode().strip()
                if error:
                    logging.error(f'❌ Error executing [{command}]: [{error}]')
                return output, error
            except Exception as e:
                logging.error(f'❌ Error executing: [{e}]')
                return None, str(e)
        else:
            return None, 'connection failed'

    def ensure_python_module_dependencies(self) -> None:
        """Make sure python module installed in libraries"""
        check_command = f'python3 -c "import _cffi_backend, yaml"'
        install_command = (
            f'echo {self.password} | sudo -S apt-get update -y && '
            f'echo {self.password} | sudo -S apt-get install -y python3-pip python3-cffi && '
            f'python3 -m pip install --upgrade pip paramiko cryptography cffi pyyaml'
        )
        
        logging.info(f"Checking VM1 for required Python dependencies using python3...")
        try:
            exit_status, _ = self.execute_command(check_command)
            # 안쪽에 exit_status = stdout.channel.recv_exit_status() 넣기
            # 설치 되었는지 확인 -> 그런데 일반적으로 잘 작동함. ??
            # 그 후 install_command 설치 유무 확인
            if exit_status == 0:
                logging.info("Required Python dependencies are already installed on VM1.")
            else:
                logging.info("Dependencies not found. Installing on VM1...")
                self.execute_command(install_command)
            logging.info("Dependencies installation completed successfully.")
        except Exception as e:
            logging.error(f"Error checking/installing dependencies on VM1: {e}")

    def file_transfer(self, src_path: str, dst_path: str) -> None:
        """Through SSH, Transfer file"""
        if not self.ssh:
            logging.error('❌ No SSH connection. Trying to reconnect...')
            self.connect()

        try:
            with self.ssh.open_sftp() as sftp:
                logging.info(f'✅ Transferring file from [{src_path}] to [{dst_path}]')
                sftp.put(src_path, dst_path)
                logging.info(f'✅ File transferred successfully')
        except Exception as e:
            logging.error(f'❌ Error transferring file: [{e}]')

    def stop_close(self) -> None:
        """Close SSH connection"""
        if self.ssh:
            self.ssh.close()
            self.ssh = None
            logging.info('☠️ Close SSH connection')