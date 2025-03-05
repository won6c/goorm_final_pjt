import re

from pygetwindow import _pygetwindow_win, getWindowsWithTitle
from win32gui import FindWindow, ShowWindow, SetForegroundWindow
from win32con import SW_MAXIMIZE, SW_MINIMIZE
from mss import mss
from numpy import ndarray, array
from cv2 import cvtColor, COLOR_BGRA2BGR, COLOR_BGR2GRAY, threshold, THRESH_BINARY, THRESH_OTSU
from pytesseract import pytesseract, image_to_string

from utils.utils import logging

pytesseract.tesseract_cmd = r'C:\Users\admin\AppData\Local\Programs\Tesseract-OCR\tesseract.exe'
# 다운로드 https://github.com/tesseract-ocr/tesseract/releases/download/5.5.0/tesseract-ocr-w64-setup-5.5.0.20241111.exe


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
            logging.info(f'✅ Get forward maximum size window successfully')
        return hwnd

    def capture_window(self, window: str) -> ndarray:
        """Capture the specific window area"""
        with mss() as sct:
            monitor = {'top': window.top, 'left': window.left, 'width': window.width, 'height': window.height}
            screenshot = sct.grab(monitor)
            img = array(screenshot)
            img = cvtColor(img, COLOR_BGRA2BGR)
            logging.info(f'✅ Capture windows and image is arranged')
            return img

    def extract_text_from_image(self, image: ndarray) -> str:
        """Extract text from image using OCR"""
        image = cvtColor(image, COLOR_BGR2GRAY)
        image = threshold(image, 0, 255, THRESH_BINARY + THRESH_OTSU)[1]
        text = image_to_string(image, lang='eng+kor')
        logging.info(f'✅ Extract text from image successfully')
        return text

    def extract_ip(self, text: str) -> str | None:
        """Extract ip in screenshot's text"""
        pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        ip = re.findall(pattern, text)
        if ip[0]:
            logging.info(f'✅ Get HOST value successfully: {ip}')
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