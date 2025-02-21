import os
import subprocess

import paramiko
from requests import get

def make_folder(path: str) -> str:
    if not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)
        print(f'✅ Creating Directory: {path}')
    else:
        print(f'⚠️ Directory is already existed: {path}')
    return path


def download_iso(iso_path: str, iso_url: str) -> None:
    if not os.path.isfile(iso_path):
        with open(iso_path, 'wb') as file:
            response = get(iso_url)
            if response.content:
                file.write(response.content)
                print(f'✅ Downloading ISO_file: {iso_path}')
            else:
                print(f'❌ Wronged ISO_url: {iso_url}')
    else:
        print(f'⚠️ ISO_file is already existed: {iso_path}')


def create_file(file_path: str, file_content: str) -> None:
    if not os.path.exists(file_path):
        print(f'✅ Creating file: {file_path}')
        with open(file_path, 'w') as file:
            file.write(file_content)
    else:
        print(f'⚠️ file is already existed: {file_path}')


def cmd_run_admin(command: str) -> str:
        try:
            result = subprocess.run([
                'powershell',
                '-Command', 'Start-Process', 'cmd',
                '-ArgumentList', f'"/c {command}"',
                '-Verb', 'runAs'
                ],
                check=True
            )
            print(f'✅ Command executed successfully: {command}')
        except subprocess.CalledProcessError as e:
            print(f'❌ Error executing command: {e}')


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
                print(f'✅ Connect {self.hostname}')
            except paramiko.AuthenticationException:
                print(f'❌ SSH Authentication failed')
                self.ssh = None
            except paramiko.SSHException as e:
                print(f'❌ SSH Connection Error: {e}')
                self.ssh = None
            except Exception as e:
                print(f'❌ Unexpected Error: {e}')
                self.ssh = None

    def execute_command(self, command: str) -> tuple[str | None, str | None]:
        """Run SSH command"""
        if not self.ssh:
            print('❌ No SSH connection. Trying to reconnect...')
            self.connect()
        
        if self.ssh:
            try:
                stdin, stdout, stderr = self.ssh.exec_command(command)
                output = stdout.read().decode().strip()
                error = stderr.read().decode().strip()
                if error:
                    print(f'❌ Error executing [{command}]: {error}')
                    
                return output, error
            except Exception as e:
                print(f'❌ Error executing: {e}')
                return None, str(e)
        else:
            return None, 'connection failed'
    
    def file_transfer(self, src_path: str, dst_path: str) -> None:
        """Through SSH, Transfer file"""
        if not self.ssh:
            print('❌ No SSH connection. Trying to reconnect...')
            self.connect()
        
        try:
            with self.ssh.open_sftp() as sftp:
                print(f'✅ Transferring file from [{src_path}] to [{dst_path}]')
                sftp.put(src_path, dst_path)
                print(f'✅ File transferred successfully')
        except Exception as e:
            print(f'❌ Error transferring file: {e}')

    def stop_close(self) -> None:
        """Close SSH connection"""
        if self.ssh:
            self.execute_command('/etc/init.d/SSH stop')
            self.ssh.close()
            self.ssh = None
            print('☠️ Close SSH connection')