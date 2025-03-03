import os
# ==========================
# 🔹 [1] Core setting value
# ==========================

ISO_URL = 'https://dl.hausmer.com/pub/VMware-VMvisor-Installer-8.0U3b-24280767.iso'  # To download iso_path(insert 💨)

ISO_NAME = 'VMware-VMvisor-Installer-8.0U3b-24280767.iso'
ENCODING = 'windows-949-2000'  # When Korean in file name & directory name
# ENCODING = 'UTF-8'  # Basic

# VMware's inner setting
CPU_COUNT = 4           # Total CPU count
RAM_COUNT = 4096        # RAM size (MB): normal 4GB
DISK_COUNT = 142        # Disk size (GB): normal 142GB
NETWORK_TYPE = 'nat'    # network method

# ESXi server infomation
HOST = '192.168.117.152'                 # ESXi's IP(insert 💨)
USER = 'root'             # ESXi's Username
PASSWORD = 'rnfma1!'      # ESXi's Password(insert 💨)

# Windows's inner setting
WINDOWS_CPU_COUNT = 2     # Total CPU count
WINDOWS_RAN_COUNT = 4096  # RAM size (MB): Normal half ESXi's RAM
WINDOWS_DISK_COUNT = 48   # Disk size (GB): Normal 48GB

# Windows server infomation
WINDOWS_HOST = '192.168.117.167'         # Windows's IP(insert 💨)
WINDOWS_USER = 'a'         # Windows's Username(insert 💨)
WINDOWS_PASSWORD = 'a'     # Windows's Password(insert 💨)
WINDOWS_SAVING_PATH = r'C:\Users\a'  # Windows's Base path saving file(insert 💨)

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
WINDOWS_ISO_PATH = r'C:\Users\admin\Downloads\Windows.iso'  # Windows_iso_path(insert 💨)

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
guestOS = "windows9-64"
ethernet0.virtualDev = "e1000e"
ethernet0.networkName = "VM Network"
ethernet0.addressType = "generated"
ethernet0.wakeOnPcktRcv = "FALSE"
ethernet0.uptCompatibility = "TRUE"
ethernet0.present = "TRUE"
sata0.present = "TRUE"
sata0:0.present = "TRUE"
sata0:0.deviceType = "cdrom-image"
sata0:0.fileName = "{WINDOWS_WORKING_DIR}/Windows.iso"
"""

# ==========================
# 🔹 [45] ELK Setting (elk_sender.py)
# ==========================

ELASTICSEARCH_URL = 'http://3.36.50.236:9200'
KIBANA_URL = 'http://3.36.50.236:5601'

INDEX_NAME = 'malware-analysis-*'
INDEX_PATTERN_TITLE = 'malware-analysis-*'
DATA_VIEW_ID = 'malware-data-view'

HEADERS_KBN_XSRF = 'true'
HEADERS_CONTENT_TYPE = 'application/json'

