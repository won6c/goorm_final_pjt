import os
import subprocess
from abc import ABC, abstractmethod

import paramiko

from utils import cmd_run_admin, download_iso, create_file, SSHClientManager

class BaseSetup(ABC):
    """Abstract class: Base class for esxi & windows VM setup"""
    
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
                print(f'✅ Creating vmdk file: {self.vmdk_path}')
                subprocess.run([
                    self.create_vmdk_path,
                    '-c',
                    '-s', f'{self.disk_count}GB',
                    '-a', 'lsilogic',
                    '-t', '1',
                    self.vmdk_path
                    ])
            else:
                print(f'⚠️ vmdk_file is already existed: {os.path.basename(self.vmdk_path)}')
        except FileNotFoundError:
            print(f"❌ VMware executable not found at {self.create_vmdk_path}. Please check the path.")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to create vmdk: {e}")

    def launch_vmware(self) -> None:
        """Run VMware Workstation"""
        try:
            print(f'✅ Launching VMware: {self.vmware_path}')
            subprocess.Popen([self.vmware_path, '-x', self.vmx_path], shell=True)
        except FileNotFoundError:
            print(f"❌ VMware executable not found at {self.vmware_path}. Please check the path.")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to launch VMware: {e}")

    def process(self):
        cmd_run_admin('bcdedit /set hypervisorlaunchtype off')
        
        download_iso(self.iso_path, self.iso_url)
        create_file(self.vmx_path, self.vmx_content)
        self.create_vmdk()
        
        self.launch_vmware()



class WindowsSetup(BaseSetup):
    """Create Windows with nested virtualization on esxi VM"""
    def __init__(self, host, user, password, windows_name, iso_path, vmx_content, disk_count) -> None:
        self.sshclient = SSHClientManager(host, user, password)
        self.windows_name = windows_name
        self.iso_path = iso_path
        self.vmx_content = vmx_content
        self.disk_count = disk_count
    
    def file_transfer(self) -> None:
        try:
            transport = paramiko.Transport(('192.168.117.152', 22))
            transport.connect(username='root', password='rnfma1!')
            sftp = paramiko.SFTPClient.from_transport(transport)

            remote_path = os.path.join('/vmfs/volumes/datastore1/iso/',os.path.basename(self.iso_path))
            sftp.put(self.iso_path, remote_path)

            sftp.close()
            transport.close()
            print(f'✅ File transferred successfully')
        except Exception as e:
            print(f'❌ Error transferring file: {e}')

    def process(self):
        self.sshclient.connect()
        
        self.sshclient.execute_command('mkdir -p /vmfs/volumes/datastore1/iso')
        
        file_list, _ = self.sshclient.execute_command('ls /vmfs/volumes/datastore1/iso')
        if os.path.basename(self.iso_path) not in file_list:
            self.file_transfer()
        
        vm_id, error = self.sshclient.execute_command(f'vim-cmd vmsvc/createdummyvm "{self.windows_name}" /vmfs/volumes/datastore1')
        if error or not vm_id:
            print('❌ Failed to retrieve VM ID')
            self.sshclient.execute_command(f'rm -rf /vmfs/volumes/datastore1/{self.windows_name}')
            return
        print(f'✅ VM Created: {vm_id}')

        self.sshclient.execute_command(f'vmkfstools -X {self.disk_count}g /vmfs/volumes/datastore1/{self.windows_name}/{self.windows_name}.vmdk')
        self.sshclient.execute_command(f'sed -i -e "/^guestOS /d" /vmfs/volumes/datastore1/{self.windows_name}/{self.windows_name}.vmx')
        
        append_vmx_command = f"""cat >> /vmfs/volumes/datastore1/{self.windows_name}/{self.windows_name}.vmx <<'EOF'
{self.vmx_content}
EOF
"""
        self.sshclient.execute_command(append_vmx_command)
        self.sshclient.execute_command(f'vim-cmd vmsvc/reload {vm_id}')
        self.sshclient.execute_command(f'vim-cmd vmsvc/power.on {vm_id}')
        print(f'✅ VM {vm_id} reloaded and powered on successfully')
        
        self.sshclient.close()