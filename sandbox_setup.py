import os
import subprocess
from requests import get
from configuration.colors import *

class BuildSandbox:
    def __init__(
        self, 
        working_dir: str, 
        vm_dir: str, 
        vm_name: str, 
        iso_url: str, 
        iso_path: str, 
        vmx_path: str, 
        vmdk_path: str, 
        vmware_path: str,
        create_vmdk_path: str,
        vmx_content: str,
        disk_count: str
        ) -> None:
        self.working_dir = working_dir
        self.vm_dir = vm_dir
        self.vm_name = vm_name
        self.iso_url = iso_url
        self.iso_path = iso_path
        self.vmx_path = vmx_path
        self.vmdk_path = vmdk_path
        self.vmware_path = vmware_path
        self.create_vmdk_path = create_vmdk_path
        self.vmx_content = vmx_content
        self.disk_count = disk_count

    def cmd_run_admin(self, command: str) -> str:
        try:
            result = subprocess.run(
                ['powershell', '-Command', f'Start-Process cmd -ArgumentList "/c {command}" -Verb runAs'],
                shell=True,
                check=True
            )
            print(f'{GREEN}[*]{RESET}Command executed successfully: {command}')
        except subprocess.CalledProcessError as e:
            print(f'{RED}[-]{RESET}Error executing command: {e}')

    def make_folder(self, name: str) -> str:
        path = os.path.join(os.getcwd(), name)
        if not os.path.isdir(path):
            os.makedirs(path, exist_ok=True)
            print(f'{GREEN}[*]{RESET} Creating Directory: {path}')
        else:
            print(f'{YELLOW}[!]{RESET} Directory is already existed: {path}')
        return path

    def download_iso(self) -> None:
        if not os.path.isfile(os.path.basename(self.iso_path)):
            with open(os.path.basename(self.iso_path), 'wb') as file:
                response = get(self.iso_url)
                file.write(response.content)
                print(f'{GREEN}[*]{RESET} Downloading ISO_file: {os.path.basename(self.iso_path)}')
        else:
            print(f'{YELLOW}[!]{RESET} ISO_file is already existed: {os.path.basename(self.iso_path)}')

    def create_file(self, file_path: str, file_content: str) -> None:
        if not os.path.exists(file_path):
            print(f'{GREEN}[*]{RESET}Creating file: {file_path}')
            with open(file_path, 'w') as file:
                file.write(file_content)
        else:
            print(f'{YELLOW}[!]{RESET} file is already existed: {file_path}')


    def create_vmdk(self) -> None:
        try:
            if not os.path.exists(self.vmdk_path):
                print(f'{GREEN}[*]{RESET} Creating vmdk file: {self.vmdk_path}')
                subprocess.run([self.create_vmdk_path, '-c', '-s', f'{self.disk_count}GB', '-a lsilogic', '-t 1', self.vmdk_path])
            else:
                print(f'{YELLOW}[!]{RESET} vmdk_file is already existed: {os.path.basename(self.vmdk_path)}')

        except FileNotFoundError:
            print(f"VMware executable not found at {self.create_vmdk_path}. Please check the path.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to create vmdk: {e}")

    def launch_vmware(self) -> None:
        try:
            print(f'{GREEN}[*]{RESET} Launching VMware: {self.vmware_path}')
            subprocess.Popen([self.vmware_path, '-x', self.vmx_path], shell=True)
        except FileNotFoundError:
            print(f"VMware executable not found at {self.vmware_path}. Please check the path.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to launch VMware: {e}")

    def process(self):
        #self.cmd_run_admin('bcdedit /set hypervisorlaunchtype off')
        
        self.make_folder(self.working_dir)
        os.chdir(self.working_dir)
        self.make_folder(self.vm_dir)
        
        self.download_iso()
        self.create_file(self.vmx_path, self.vmx_content)
        self.create_vmdk()
        
        self.launch_vmware()