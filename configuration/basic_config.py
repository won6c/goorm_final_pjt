import os

# 수정할 설정
HOME_DIR = os.path.expanduser('~')
WORKING_DIR_NAME = 'sandbox'
VM_NAME = 'ESXi_sandbox'
ISO_URL = '<to download iso_path>'
ISO_NAME = 'VMware-VMvisor-Installer-8.0U3b-24280767.iso'
VMWARE_PATH = r'C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe'
CREATE_VMDK_PATH = r'C:\Program Files (x86)\VMware\VMware Workstation\vmware-vdiskmanager.exe'
# ENCODING = 'UTF-8'                  # 기본
ENCODING = 'windows-949-2000'     # 파일명에 한글이 들어가 있을 때

# ESXi 설정
HOST = '192.168.117.152'    # ESXi's IP
USER = 'root'               # ESXi's Username
PASSWORD = 'rnfma1!'       # ESXi's Password

WINDOWS_NAME = 'windows_sandbox'
WINDOWS_ISO_PATH = os.path.join(HOME_DIR, 'Downloads', 'Windows.iso')

# VMware의 내부 설정
CPU_COUNT = 4           # 총 CPU 개수
RAM_COUNT = 4096        # RAM 용량 MB(기본 4GB)
DISK_COUNT = 142        # 디스크 크기 GB(기본 142GB)
NETWORK_TYPE = 'nat'    # 네트워크 방식

# Windows의 내부 설정
WINDOWS_CPU_COUNT = 2
WINDOWS_RAN_COUNT = 2048
WINDOWS_DISK_COUNT = 60  # 디스크 크기 GB

# 기본 설정
DESKTOP_DIR = os.path.join(HOME_DIR, 'Desktop')
WORKING_DIR = os.path.join(DESKTOP_DIR, WORKING_DIR_NAME)
VM_DIR = os.path.join(WORKING_DIR, 'vmware', VM_NAME)
ISO_PATH = os.path.join(WORKING_DIR, ISO_NAME)
VMX_PATH = os.path.join(VM_DIR, f'{VM_NAME}.vmx')
VMDK_PATH = os.path.join(VM_DIR, f'{VM_NAME}.vmdk')

VMX_CONTENT = f""".encoding = "{ENCODING}"
config.version = "8"
virtualHW.version = "21"
pciBridge0.present = "TRUE"
pciBridge4.present = "TRUE"
pciBridge4.virtualDev = "pcieRootPort"
pciBridge4.functions = "8"
pciBridge5.present = "TRUE"
pciBridge5.virtualDev = "pcieRootPort"
pciBridge5.functions = "8"
pciBridge6.present = "TRUE"
pciBridge6.virtualDev = "pcieRootPort"
pciBridge6.functions = "8"
pciBridge7.present = "TRUE"
pciBridge7.virtualDev = "pcieRootPort"
pciBridge7.functions = "8"
vmci0.present = "TRUE"
hpet0.present = "TRUE"
nvram = "{VM_NAME}.nvram"
virtualHW.productCompatibility = "hosted"
powerType.powerOff = "soft"
powerType.powerOn = "soft"
powerType.suspend = "soft"
powerType.reset = "soft"
displayName = "{VM_NAME}"
firmware = "efi"
guestOS = "vmkernel8"
vhv.enable = "TRUE"
tools.syncTime = "FALSE"
numvcpus = "{CPU_COUNT}"
cpuid.coresPerSocket = "2"
memsize = "{RAM_COUNT}"
scsi0.virtualDev = "pvscsi"
scsi0.present = "TRUE"
scsi0:0.fileName = "{VM_NAME}.vmdk"
scsi0:0.present = "TRUE"
ide1:0.deviceType = "cdrom-image"
ide1:0.fileName = "{ISO_PATH}"
ide1:0.present = "TRUE"
usb.present = "TRUE"
ehci.present = "TRUE"
ethernet0.connectionType = "{NETWORK_TYPE}"
ethernet0.addressType = "generated"
ethernet0.virtualDev = "vmxnet3"
ethernet0.present = "TRUE"
extendedConfigFile = "{VM_NAME}.vmxf"
floppy0.present = "FALSE"
"""

WINDOWS_VMX_CONTENT = f"""numvcpus = "{WINDOWS_CPU_COUNT}"
memSize = "{WINDOWS_RAN_COUNT}"
guestOS = "windows9-64"
ethernet0.virtualDev = "vmxnet3"
ethernet0.networkName = "VM Network"
ethernet0.addressType = "generated"
ethernet0.wakeOnPcktRcv = "FALSE"
ethernet0.uptCompatibility = "TRUE"
ethernet0.present = "TRUE"
sata0.present = "TRUE"
sata0:0.present = "TRUE"
sata0:0.deviceType = "cdrom-image"
sata0:0.fileName = "/vmfs/volumes/datastore1/iso/Windows.iso"
"""