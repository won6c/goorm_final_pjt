import time

import paramiko
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException

from utils.utils import logging


class SSHClientManager:
    """Run command while connect SSH"""
    def __init__(self, hostname: str, username: str, password: str = None) -> None:
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
                else:
                    logging.info(f'✅ Execute command successfully: [{command}]')
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
    def __init__(self, host: str, username: str, password: str = None) -> None:
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
            time.sleep(1)
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