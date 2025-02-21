import argparse

from configuration.basic_config import *
from build_sandbox import ESXiSetup, WindowsSetup

def init_argparse() -> argparse.ArgumentParser:
    """Initialize ArgumentParser & options addition"""
    parser = argparse.ArgumentParser()
    parser.add_argument('-E', dest='ESXi', action='store_true', help='ESXi install')
    parser.add_argument('-W', dest='Windows', action='store_true', help='Windows install')
    return parser


def option(options: argparse.Namespace) -> None:
    """Execute according to the option"""
    if options.ESXi:
        esxi_setup = ESXiSetup(ISO_URL, ISO_PATH, VMX_PATH, VMDK_PATH, VMWARE_PATH, CREATE_VMDK_PATH, VMX_CONTENT, DISK_COUNT)
        esxi_setup.process()
    elif options.Windows:
        window_setup = WindowsSetup(HOST, USER, PASSWORD, WINDOWS_ISO_PATH, WINDOWS_VMX_PATH, WINDOWS_VMDK_PATH, WINDOWS_WORKING_DIR, WINDOWS_NAME, WINDOWS_VMX_CONTENT, WINDOWS_DISK_COUNT)
        window_setup.process()