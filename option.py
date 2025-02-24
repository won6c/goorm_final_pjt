import argparse

from configuration.basic_config import *
from setup.build_sandbox import ESXiSetup, WindowsSetup
from setup.utils import SSHClientManager

def init_argparse() -> argparse.ArgumentParser:
    """Initialize ArgumentParser & options addition"""
    parser = argparse.ArgumentParser(
        description='Host → VM1 file transfer + upload scripts + run vm1_to_vm2.py on VM1'
    )
    parser.add_argument('-E', dest='esxi', action='store_true', help='ESXi install')
    parser.add_argument('-W', dest='windows', action='store_true', help='Windows install')
    
    parser.add_argument('-F', dest='file', required=True, help='File path on Host PC to send to VM1')
    parser.add_argument('-HE', dest='host_to_esxi', action='store_true', help='Transfer file from host to esxi')
    parser.add_argument('-EW', dest='esxi_to_windows', action='store_true', help='Transfer file from esxi to windows')
    return parser


def option(options: argparse.Namespace) -> None:
    """Execute according to the option"""
    if options.esxi:
        esxi_setup = ESXiSetup(ISO_URL, ISO_PATH, VMX_PATH, VMDK_PATH, VMWARE_PATH, CREATE_VMDK_PATH, VMX_CONTENT, DISK_COUNT)
        esxi_setup.process()
    elif options.windows:
        window_setup = WindowsSetup(HOST, USER, PASSWORD, WINDOWS_ISO_PATH, WINDOWS_VMX_PATH, WINDOWS_VMDK_PATH, WINDOWS_WORKING_DIR, WINDOWS_NAME, WINDOWS_VMX_CONTENT, WINDOWS_DISK_COUNT)
        window_setup.process()
    
    if options.host_to_esxi | options.esxi_to_windows:
        ssh = SSHClientManager(HOST, USER, PASSWORD)
        ssh.connect()
        if options.host_to_esxi:
            ssh.execute_command(f'mkdir -p {SAVING_PATH}')
            remote_file_path = os.path.join(SAVING_PATH, os.path.basename(options.file))
            ssh.file_transfer(options.file, remote_file_path)
            
        if options.esxi_to_windows:
            ssh.ensure_python_module_dependencies()