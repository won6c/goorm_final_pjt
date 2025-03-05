import os
import subprocess
import logging

from requests import get

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


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