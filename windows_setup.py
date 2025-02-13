import os
import paramiko
from configuration.colors import *

class BuildWindows:
    def __init__(self, host, user, password, windows_name, windows_iso_path) -> None:
        self.host = host
        self.user = user
        self.password = password
        self.windows_name = windows_name
        self.windows_iso_path = windows_iso_path
    
    def file_transfer(self) -> None:
        try:
            transport = paramiko.Transport((self.host, 22))
            transport.connect(username=self.user, password=self.password)
            sftp = paramiko.SFTPClient.from_transport(transport)

            remote_path = os.path.join('/vmfs/volumes/datastore1/iso/',os.path.basename(self.windows_iso_path))
            sftp.put(self.windows_iso_path, remote_path)

            sftp.close()
            transport.close()
            print(f'{GREEN}[*]{RESET} File transferred successfully')
        except Exception as e:
            print(f'{RED}[-]{RESET} Error transferring file: {e}')
    
    def ssh_command(self, command) -> None:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh.connect(hostname=self.host, username=self.user, password=self.password)
            stdin, stdout, stderr = ssh.exec_command(command)
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            
            if error:
                print(f'Error executing {command}: {error}')
            
            return output
        except Exception as e:
            print(f'SSH Connection Error: {e}')
            return None
        finally:
            ssh.close()

    def process(self):
        self.ssh_command('mkdir /vmfs/volumes/datastore1/iso')
        
        file_list = self.ssh_command('ls /vmfs/volumes/datastore1/iso')
        if not 'Windows.iso' in file_list:
            self.file_transfer()
        
        vm_id = self.ssh_command(f'vim-cmd vmsvc/createdummyvm "{self.windows_name}" /vmfs/volumes/datastore1')
        print(f'VM Created: {vm_id}')
        
        vm_id = vm_id.split()[-1] if vm_id else None
        if not vm_id:
            print('Failed to retrieve VM ID')
            self.ssh_command(f'rm -rf /vmfs/volumes/datastore1/{self.windows_name}')
            return
        
        self.ssh_command(f'vmkfstools -X 60g /vmfs/volumes/datastore1/{self.windows_name}/{self.windows_name}.vmdk')
        
        self.ssh_command(f'sed -i -e "/^guestOS /d" /vmfs/volumes/datastore1/{self.windows_name}/{self.windows_name}.vmx')
        
        append_vmx_command = f"""cat >> /vmfs/volumes/datastore1/{self.windows_name}/{self.windows_name}.vmx <<'EOF'
numvcpus = "2"
memSize = "4096"
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
EOF
"""
        self.ssh_command(append_vmx_command)
        self.ssh_command(f'vim-cmd vmsvc/reload {vm_id}')
        print(f'VM {vm_id} reloaded successfully')
        poweron_command = f'vim-cmd vmsvc/power.on {vm_id}'
        tmp = self.ssh_command(poweron_command)
        print(f'delete guestOS: {tmp}')