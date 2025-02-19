from configuration.basic_config import *
from build_sandbox import ESXiSetup, WindowsSetup
from utils import make_folder

def main():
    make_folder(VM_DIR)
    #esxi_setup = ESXiSetup(ISO_URL, ISO_PATH, VMX_PATH, VMDK_PATH, VMWARE_PATH, CREATE_VMDK_PATH, VMX_CONTENT, DISK_COUNT)
    #esxi_setup.process()
    
    window_setup = WindowsSetup(HOST, USER, PASSWORD, WINDOWS_NAME, WINDOWS_ISO_PATH, WINDOWS_VMX_CONTENT, WINDOWS_DISK_COUNT)
    window_setup.process()

if __name__ == '__main__':
    main()