import windows_setup
from configuration.config import *
def main():
    setup = windows_setup.BuildWindows(HOST, USER, PASSWARD, WINDOWS_NAME, WINDOWS_ISO_PATH)
    setup.process()

if __name__ == '__main__':
    main()