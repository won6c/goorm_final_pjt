import os
import re
import subprocess
from abc import ABC, abstractmethod

from utils.utils import logging, make_folder, cmd_run_admin, download_iso, create_file
from utils.ssh_utils import SSHClientManager, SSHEnable
from configuration.basic_config import VM_DIR, WORKING_DIR


class BaseSetup(ABC):
    """Abstract class: Base class for ESXi & Windows VM setup"""
    @abstractmethod
    def process(self):
        """Run automated code"""
        pass


class ESXiSetup(BaseSetup):
    """Create ESXi with VMware Workstation on local host"""
    def __init__(
        self, 
        iso_url: str, 
        iso_path: str, 
        vmx_path: str, 
        vmdk_path: str, 
        vmware_path: str,
        create_vmdk_path: str,
        vmx_content: str,
        disk_count: str
        ) -> None:
        self.iso_url = iso_url
        self.iso_path = iso_path
        self.vmx_path = vmx_path
        self.vmdk_path = vmdk_path
        self.vmware_path = vmware_path
        self.create_vmdk_path = create_vmdk_path
        self.vmx_content = vmx_content
        self.disk_count = disk_count

    def create_vmdk(self) -> None:
        """Create VMDK extention to save on hard disk"""
        try:
            if not os.path.exists(self.vmdk_path):
                logging.info(f'✅ Creating vmdk file: {self.vmdk_path}')
                subprocess.run([
                    self.create_vmdk_path,
                    '-c',
                    '-s', f'{self.disk_count}GB',
                    '-a', 'lsilogic',
                    '-t', '1',
                    self.vmdk_path
                    ])
            else:
                logging.warning(f'⚠️ vmdk_file is already existed: {os.path.basename(self.vmdk_path)}')
        except FileNotFoundError:
            logging.error(f"❌ VMware executable not found at {self.create_vmdk_path}. Please check the path.")
        except subprocess.CalledProcessError as e:
            logging.error(f"❌ Failed to create vmdk: {e}")

    def launch_vmware(self) -> None:
        """Run VMware Workstation"""
        try:
            logging.info(f'✅ Launching VMware: {self.vmware_path}')
            subprocess.Popen([self.vmware_path, '-x', self.vmx_path], shell=True)
        except FileNotFoundError:
            logging.error(f"❌ VMware executable not found at {self.vmware_path}. Please check the path.")
        except subprocess.CalledProcessError as e:
            logging.error(f"❌ Failed to launch VMware: {e}")

    def process(self):
        make_folder(VM_DIR)

        enable_nested_virtualization = os.path.join(WORKING_DIR, 'enable_nested_virtualization.txt')
        cmd_run_admin(f'bcdedit /enum > {enable_nested_virtualization}')
        with open(enable_nested_virtualization, 'r') as file:
            content = file.read()
        if not re.search(r'hypervisorlaunchtype\s+Off', content):
            cmd_run_admin(rf'bcdedit /set hypervisorlaunchtype off & del {enable_nested_virtualization} & shutdown \r \t 0')

        download_iso(self.iso_path, self.iso_url)
        create_file(self.vmx_path, self.vmx_content)
        self.create_vmdk()

        self.launch_vmware()

class WindowsSetup(BaseSetup):
    """Create Windows with nested virtualization on ESXi VM"""
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        iso_path: str,
        working_dir: str,
        windows_name: str,
        vmx_content: str,
        disk_count: str
        ) -> None:
        self.sshclient = SSHClientManager(host, username, password)
        self.host = host
        self.username = username
        self.password = password
        self.iso_path = iso_path
        self.working_dir = working_dir
        self.windows_name = windows_name
        self.vmx_content = vmx_content
        self.disk_count = disk_count
        self.vmx_path = f'{working_dir}/{windows_name}/{windows_name}.vmx'
        self.vmdk_path = f'{working_dir}/{windows_name}/{windows_name}.vmdk'

        self.iso_dir = f'{self.working_dir}/iso'
        self.windows_dir = f'{self.working_dir}/{self.windows_name}'
        self.iso_filename = os.path.basename(self.iso_path)

    def process(self) -> None:
        SSHEnable(self.host, self.username, self.password).ssh_enable()
        self.sshclient.connect()

        self.sshclient.execute_command(f'mkdir -p {self.iso_dir}')

        file_list, _ = self.sshclient.execute_command(f'ls {self.iso_dir}')
        if self.iso_filename not in file_list:
            self.sshclient.file_transfer(self.iso_path, self.iso_dir+'/'+self.iso_filename)

        vm_id, error = self.sshclient.execute_command(f'vim-cmd vmsvc/createdummyvm "{self.windows_name}" {self.working_dir}')
        if error or not vm_id:
            logging.error('❌ Failed to retrieve VM ID')
            self.sshclient.execute_command(f'rm -rf {self.windows_dir}')
            return
        logging.info(f'✅ VM Created: {vm_id}')

        self.sshclient.execute_command(f'sed -i -e \'s/^scsi0.virtualDev .*/scsi0.virtualDev = "lsisas1068"/\' {self.vmx_path}')
        self.sshclient.execute_command(f'sed -i -e \'s/^guestOS .*/guestOS = "windows9-64"/\' {self.vmx_path}')
        append_vmx_command = f"""cat >> {self.vmx_path} <<'EOF'
{self.vmx_content}
EOF
"""
        self.sshclient.execute_command(f'vmkfstools -X {self.disk_count}g {self.vmdk_path}')
        self.sshclient.execute_command(append_vmx_command)
        self.sshclient.execute_command(f'vim-cmd vmsvc/reload {vm_id}')
        self.sshclient.execute_command(f'vim-cmd vmsvc/power.on {vm_id}')
        logging.info(f'✅ VM {vm_id} reloaded and powered on successfully')

        self.sshclient.close()