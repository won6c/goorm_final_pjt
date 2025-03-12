import argparse

from configuration.basic_config import *
from setup.build_sandbox import ESXiSetup, WindowsSetup
from utils.ssh_utils import SSHClientManager, SSHEnable
import utils.make_pdf as make_pdf


def init_argparse() -> argparse.ArgumentParser:
    """Initialize ArgumentParser & options addition"""
    parser = argparse.ArgumentParser()
    parser.add_argument('-E', dest='esxi_name', action='store_true', help='Install ESXi')
    parser.add_argument('-W', dest='windows_name', nargs='?', const=WINDOWS_NAME, help='Install Windows(insert windows_name, default_name = "Windows_sandbox")')

    parser.add_argument('-F', dest='file', help='Input file path on Host to send to VM')

    parser.add_argument('-S', dest='ssh', choices=['on', 'off'], help='Enable or Disable SSH')
    parser.add_argument('-N', dest='network', choices=['nat', 'only'], help='Choose network method(nat or host_only)')
    parser.add_argument('-I', dest='internet', choices=['on', 'off'], help='Enable or Disable internet')
    parser.add_argument('-SN', dest='snapshot', choices=['get', 'create', 'revert', 'remove'], help='Capture snapshot on windows')

    parser.add_argument('-O', dest='output', help='Input file name and get analysis PDF file')
    return parser


def option(options: argparse.Namespace) -> None:
    """Execute according to the option"""
    if options.esxi_name:
        ESXiSetup(ISO_URL, ISO_PATH, VMX_PATH, VMDK_PATH, VMWARE_PATH, CREATE_VMDK_PATH, VMX_CONTENT, DISK_COUNT).process()

    if options.windows_name:
        WindowsSetup(HOST, USER, PASSWORD, WINDOWS_ISO_URL, WINDOWS_ISO_PATH, WINDOWS_WORKING_DIR, options.windows_name, WINDOWS_VMX_CONTENT, WINDOWS_DISK_COUNT).process()

    if options.file:
        ssh = SSHClientManager(WINDOWS_HOST, WINDOWS_USER, WINDOWS_PASSWORD)
        ssh.connect()
        remote_dir_path = os.path.join(WINDOWS_SAVING_PATH, 'file')
        ssh.execute_command(f'mkdir -p {remote_dir_path}')
        remote_file_path = f'{remote_dir_path}/{os.path.basename(options.file)}'
        ssh.file_transfer(options.file, remote_file_path)
        ssh.close()

    if options.ssh == 'on':
        SSHEnable(HOST, USER, PASSWORD).ssh_enable()
    elif options.ssh == 'off':
        SSHEnable(HOST, USER, PASSWORD).ssh_disable()

    if options.network or options.internet or options.snapshot:
        ssh = SSHClientManager(HOST, USER, PASSWORD)
        ssh.connect()
        vm_id, _ = ssh.execute_command(f'vim-cmd vmsvc/getallvms | grep "{WINDOWS_NAME}" | awk \'{{print $1}}\'')

        if options.network == 'nat':
            ssh.execute_command(f'vim-cmd vmsvc/power.off {vm_id}')
            ssh.execute_command(f'sed -i -e \'s/^ethernet0.networkName = .*/ethernet0.networkName = "VM Network"/\' {WINDOWS_WORKING_DIR}/{WINDOWS_NAME}/{WINDOWS_NAME}.vmx')
            ssh.execute_command(f'vim-cmd vmsvc/power.on {vm_id}')
        elif options.network == 'only':
            result, _ = ssh.execute_command('esxcli network vswitch standard list')
            if 'host_only' not in result:
                ssh.execute_command('esxcli network vswitch standard add -v host_only')
                ssh.execute_command('esxcli network vswitch standard portgroup add -p host_only -v host_only')

            ssh.execute_command(f'vim-cmd vmsvc/power.off {vm_id}')
            ssh.execute_command(f'sed -i -e \'s/^ethernet0.networkName = .*/ethernet0.networkName = "host_only"/\' {WINDOWS_WORKING_DIR}/{WINDOWS_NAME}/{WINDOWS_NAME}.vmx')
            ssh.execute_command(f'vim-cmd vmsvc/power.on {vm_id}')

        if options.internet == 'on':
            ssh.execute_command('esxcli network vswitch standard portgroup policy failover set -p "VM Network" -a vmnic0')
        elif options.internet == 'off':
            ssh.execute_command('esxcli network vswitch standard portgroup policy failover set -p "VM Network" -a ""')

        if options.snapshot == 'get':
            snapshot_state, _ = ssh.execute_command(f'vim-cmd vmsvc/snapshot.get {vm_id}')
            print('='*50)
            print(snapshot_state)
            print('='*50)
        elif options.snapshot == 'create':
            name = input('Input snapshot_name: ')
            description = input('Input snapshot_description: ')
            mem = input('Include RAM[0=not include, 1=include]: ')
            sespend = input('Whether or not suspend[0=run, 1=suspend]: ')

            ssh.execute_command(f'vim-cmd vmsvc/snapshot.create {vm_id} {name} {description} {mem} {sespend}')
        elif options.snapshot == 'revert':
            snapshot_id = input('Input snapshot_id: ')
            power_maintain = input('Input VM power state[0=vm power state maintain and revert, 1=shutdown power and revert]: ')

            ssh.execute_command(f'vim-cmd vmsvc/snapshot.revert {vm_id} {snapshot_id} {power_maintain}')
            ssh.execute_command(f'vim-cmd vmsvc/power.on {vm_id}')
        elif options.snapshot == 'remove':
            snapshot_id = input('Input snapshot_id: ')

            ssh.execute_command(f'vim-cmd vmsvc/snapshot.remove {vm_id} {snapshot_id}')

        if ssh:
            ssh.close()

    if options.output:
        make_pdf.process(f'{options.output}-*')