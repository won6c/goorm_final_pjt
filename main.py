import sandbox_setup
from configuration.basic_config import *

def main():
    setup = sandbox_setup.BuildSandbox(WORKING_DIR, VM_DIR, VM_NAME, ISO_URL, ISO_PATH, VMX_PATH, VMDK_PATH, VMWARE_PATH, CREATE_VMDK_PATH, VMX_CONTENT, DISK_COUNT)
    setup.process()

if __name__ == '__main__':
    main()