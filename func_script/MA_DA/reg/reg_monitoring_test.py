import winreg
import win32api
import win32con
import win32event


REG_NOTIFY_CHANGE_NAME=0x00000001
REG_NOTIFY_CHANGE_LAST_SET=0x00000004

def monitor_registry_key(key_path):
    # 레지스트리 키 열기
    registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ | winreg.KEY_NOTIFY)
    # 변경 알림 설정
    win32api.RegNotifyChangeKeyValue(
        registry_key,
        True,
        REG_NOTIFY_CHANGE_NAME |
        win32con.REG_NOTIFY_CHANGE_ATTRIBUTES |
        REG_NOTIFY_CHANGE_LAST_SET |
        win32con.REG_NOTIFY_CHANGE_SECURITY,
        None,
        False
    )
    print(f"Monitoring changes in: {key_path}")

    try:
        # 무한 루프를 돌며 변경을 감지
        while True:
            result = win32event.WaitForSingleObject(win32event.CreateEvent(None, 0, 0, None), 500)
            if result == win32event.WAIT_OBJECT_0:
                print("Registry key changed!")
                break
    except KeyboardInterrupt:
        print("Monitoring stopped.")

if __name__ == "__main__":
    # 모니터링할 레지스트리 키 경로 설정
    key_path = r"Software\\"
    monitor_registry_key(key_path)
