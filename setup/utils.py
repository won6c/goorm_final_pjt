import os
import subprocess
import logging
import re

import paramiko
from requests import get
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from pygetwindow import _pygetwindow_win, getWindowsWithTitle
from win32gui import FindWindow, ShowWindow, SetForegroundWindow
from win32con import SW_MAXIMIZE, SW_MINIMIZE
from mss import mss
from numpy import ndarray, array
from cv2 import cvtColor, COLOR_BGRA2BGR, COLOR_BGR2GRAY, threshold, THRESH_BINARY, THRESH_OTSU
from pytesseract import pytesseract, image_to_string

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
pytesseract.tesseract_cmd = r'C:\Users\admin\AppData\Local\Programs\Tesseract-OCR\tesseract.exe'
# 다운로드 https://github.com/tesseract-ocr/tesseract/releases/download/5.5.0/tesseract-ocr-w64-setup-5.5.0.20241111.exe


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

    def close(self) -> None:
        """Close SSH connection"""
        if self.ssh:
            self.ssh.close()
            self.ssh = None
            logging.info('☠️ Close SSH connection')


class SSHEnable:
    """Enable SSH with selenium"""
    def __init__(self, host, username, password=None) -> None:
        self.host = host
        self.username = username
        self.password = password
        
    def init_webdriver(self) -> webdriver.Chrome:
        """Initialize Chrome WebDriver"""
        options = webdriver.ChromeOptions()
        options.add_argument('--ignore-certificate-errors')
        
        driver = webdriver.Chrome(service=Service(), options=options)
        driver.maximize_window()
        return driver
    
    def find_click(self, driver: webdriver.Chrome, by: By, value: str, timeout: int = 10) -> bool:
        """Find & click a web element"""
        try:
            WebDriverWait(driver, timeout).until(EC.element_to_be_clickable((by, value))).click()
            return True
        except TimeoutException:
            logging.error(f'❌ Not found: [{value}]')
            return False
        except Exception as e:
            logging.error(f'❌ Unexpected Error: [{e}]')
            return False
    
    def login_esxi(self, driver: webdriver.Chrome, timeout: int = 10) -> bool:
        """Login to ESXi web"""
        driver.get(f'https://{self.host}/ui/#/host/manage/services')
        try:
            WebDriverWait(driver, timeout).until(EC.presence_of_element_located((By.ID, 'username'))).send_keys(self.username)
            WebDriverWait(driver, timeout).until(EC.presence_of_element_located((By.ID, 'password'))).send_keys(self.password)
            if self.find_click(driver, By.XPATH, '//button[@type="submit"]'):
                logging.info('✅ Login successfully')
                return True
        except TimeoutException:
            logging.error(f'❌ Fail loading login page')
        except NoSuchElementException:
            logging.error(f'❌ Not found login element')
        return False
    
    def ssh_enable(self) -> None:
        """Enable SSH on ESXi web"""
        driver = self.init_webdriver()
        try:
            if self.login_esxi(driver):
                self.find_click(driver, By.XPATH, '//button[contains(@class, "btn-primary") and text()="확인"]', 3)
                if self.find_click(driver, By.XPATH, '//div[contains(text(), "TSM-SSH")]'):
                    logging.info(f'✅ TSM-SSH service clicked successfully')

                    if self.find_click(driver, By.XPATH, '//a[contains(@title, "시작")]'):
                        logging.info(f'✅ Activate SSH successfully')
        except Exception as e:
            logging.error(f'❌ Unexpected Error: [{e}]')
        finally:
            driver.quit()
    
    def ssh_disable(self) -> None:
        """Enable SSH on ESXi web"""
        driver = self.init_webdriver()
        try:
            if self.login_esxi(driver):
                self.find_click(driver, By.XPATH, '//button[contains(@class, "btn-primary") and text()="확인"]', 3)
                if self.find_click(driver, By.XPATH, '//div[contains(text(), "TSM-SSH")]'):
                    logging.info(f'✅ TSM-SSH service clicked successfully')

                    if self.find_click(driver, By.XPATH, '//a[contains(@title, "중지")]'):
                        logging.info(f'✅ Activate SSH successfully')
        except Exception as e:
            logging.error(f'❌ Unexpected Error: [{e}]')
        finally:
            driver.quit()


class ObtainIP:
    """Take a screenshot and obtain the IP through tesseract(OCR)"""
    def __init__(self):
        pass

    def get_window(self, window_name: str) -> None | _pygetwindow_win.Win32Window:
        """Find window's coordinate and size"""
        windows = getWindowsWithTitle(window_name)
        if not windows:
            logging.error(f'❌ Not find: [{window_name}]')
            return None
        logging.info(f'✅ Get window: [{window_name}]')
        return windows[0]

    def bring_window_to_front(self, window_title: str) -> int:
        """Size up and move forward window"""
        hwnd = FindWindow(None, window_title)
        if hwnd:
            ShowWindow(hwnd, SW_MAXIMIZE)
            SetForegroundWindow(hwnd)
        return hwnd

    def capture_window(self, window: str) -> ndarray:
        """Capture the specific window area"""
        with mss() as sct:
            monitor = {'top': window.top, 'left': window.left, 'width': window.width, 'height': window.height}
            screenshot = sct.grab(monitor)
            img = array(screenshot)
            img = cvtColor(img, COLOR_BGRA2BGR)
            return img

    def extract_text_from_image(self, image: ndarray) -> str:
        """Extract text from image using OCR"""
        image = cvtColor(image, COLOR_BGR2GRAY)
        image = threshold(image, 0, 255, THRESH_BINARY + THRESH_OTSU)[1]
        text = image_to_string(image, lang='eng+kor')
        return text

    def extract_ip(self, text: str) -> str | None:
        """Extract ip in screenshot's text"""
        pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        ip = re.findall(pattern, text)
        if ip[0]:
            logging.info(f'✅ Get HOST value successfully: [{ip}]')
            return ip[0]
        else:
            logging.error(f'✅ Not find host_ip value')
            return None

    def update_config_file(self, ip: str) -> None:
        """Update HOST value of basic_config.py"""
        try:
            with open(r'configuration\basic_config.py', 'r', encoding='utf-8') as file:
                lines = file.readlines()

            updated_lines = []
            for line in lines:
                if line.strip().startswith('HOST = '):
                    updated_line = f"HOST = '{ip}'  # ESXi's IP(insert 💨)\n"
                    updated_lines.append(updated_line)
                else:
                    updated_lines.append(line)

            with open(r'configuration\basic_config.py', 'w', encoding='utf-8') as file:
                file.writelines(updated_lines)

            logging.info('✅ Update config file successfully')

        except Exception as e:
            logging.error(f'❌ Error updating file: [{e}]')

    def process(self) -> None:
        vm_window = self.get_window('VMware Workstation')
        if vm_window:
            hwnd = self.bring_window_to_front(vm_window.title)
            image = self.capture_window(vm_window)
            text = self.extract_text_from_image(image)
            ip = self.extract_ip(text)
            ShowWindow(hwnd, SW_MINIMIZE)
            self.update_config_file(ip)