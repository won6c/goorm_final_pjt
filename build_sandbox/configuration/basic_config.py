import os
# ==========================
# 🔹 [1] Core setting value
# ==========================

AWS_IP = ''  # AWS IP(insert 💨)
ELASTICSEARCH_URL = f'http://{AWS_IP}:9200'

ISO_URL = ''          # To download iso_path(insert 💨)
WINDOWS_ISO_URL = ''  # To download iso_path(insert 💨)

ISO_NAME = 'ESXI-8.0U3B-24280767-STANDARD.iso'
ENCODING = 'windows-949-2000'  # When Korean in file name & directory name
# ENCODING = 'UTF-8'  # Basic

# VMware's inner setting
CPU_COUNT = 4           # Total CPU count
RAM_COUNT = 4096        # RAM size (MB): normal 4GB
DISK_COUNT = 142        # Disk size (GB): normal 142GB
NETWORK_TYPE = 'nat'    # network method

# ESXi server infomation
HOST = '192.168.117.10'  # ESXi's IP
USER = 'root'            # ESXi's Username
PASSWORD = 'rnfma1!'     # ESXi's Password

# Windows's inner setting
WINDOWS_CPU_COUNT = 2     # Total CPU count
WINDOWS_RAN_COUNT = 4096  # RAM size (MB): Normal half ESXi's RAM
WINDOWS_DISK_COUNT = 48   # Disk size (GB): Normal 48GB

# Windows server infomation
WINDOWS_HOST = ''                               # Windows's IP(insert 💨)
WINDOWS_USER = 'User'                           # Windows's Username
WINDOWS_PASSWORD = 'rnfma1!'                    # Windows's Password
WINDOWS_SAVING_PATH = r'C:\Users\User\desktop'  # Windows's Base path saving file

# ==========================
# 🔹 [2] Path setting
# ==========================

HOME_DIR = os.path.expanduser('~')
DESKTOP_DIR = os.path.join(HOME_DIR, 'Desktop')

WORKING_DIR_NAME = 'sandbox'
WORKING_DIR = os.path.join(DESKTOP_DIR, WORKING_DIR_NAME)

VM_NAME = 'ESXi_sandbox'
VM_DIR = os.path.join(WORKING_DIR, 'vmware', VM_NAME)
ISO_PATH = os.path.join(WORKING_DIR, ISO_NAME)

VMX_PATH = os.path.join(VM_DIR, f'{VM_NAME}.vmx')
VMDK_PATH = os.path.join(VM_DIR, f'{VM_NAME}.vmdk')

WINDOWS_NAME = 'Windows_sandbox'
WINDOWS_WORKING_DIR = '/vmfs/volumes/datastore1'
WINDOWS_ISO_NAME = 'Windows10.iso'
WINDOWS_ISO_PATH = os.path.join(WORKING_DIR, WINDOWS_ISO_NAME)

# ==========================
# 🔹 [3] VMware execute file path
# ==========================

VMWARE_PATH = r'C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe'
CREATE_VMDK_PATH = r'C:\Program Files (x86)\VMware\VMware Workstation\vmware-vdiskmanager.exe'

# ==========================
# 🔹 [4] VM setup file (VMX) template
# ==========================

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
ethernet0.virtualDev = "e1000e"
ethernet0.networkName = "VM Network"
ethernet0.addressType = "generated"
ethernet0.wakeOnPcktRcv = "FALSE"
ethernet0.present = "TRUE"
sata0.present = "TRUE"
sata0:0.present = "TRUE"
sata0:0.deviceType = "cdrom-image"
sata0:0.fileName = "{WINDOWS_WORKING_DIR}/iso/{WINDOWS_ISO_NAME}"
powerType.suspend = "soft"
firmware = "efi"
uefi.secureBoot.enabled = "TRUE"
svga.autodetect = "TRUE"
svga.vramSize = "16777216"
usb_xhci:4.present = "TRUE"
usb_xhci.present = "TRUE"
usb_xhci:4.deviceType = "hid"
usb_xhci:4.port = "4"
usb_xhci:4.parent = "-1"
"""