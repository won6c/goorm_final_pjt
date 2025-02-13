from configuration.basic_config import *
import sandbox_setup
import windows_setup

def main():
    setup = sandbox_setup.BuildSandbox(WORKING_DIR, VM_DIR, VM_NAME, ISO_URL, ISO_PATH, VMX_PATH, VMDK_PATH, VMWARE_PATH, CREATE_VMDK_PATH, VMX_CONTENT, DISK_COUNT)
    setup.process()
    window_setup = windows_setup.BuildWindows(HOST, USER, PASSWARD, WINDOWS_NAME, WINDOWS_ISO_PATH)
    window_setup.process()

if __name__ == '__main__':
    main()