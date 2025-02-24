#!/usr/bin/env python3
import os
from setup.utils import SSHClientManager
import argparse
import logging
from configuration.basic_config import *
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def main():
    parser = argparse.ArgumentParser(
        description="Host → VM1 file transfer + upload scripts + run vm1_to_vm2.py on VM1"
    )
    parser.add_argument("--file", required=True, help="File path on Host PC to send to VM1")
    parser.add_argument("--config", default="config.yaml", help="Path to the configuration file (default: config.yaml)")
    parser.add_argument("--script", default="vm1_to_vm2.py", help="Path to vm1_to_vm2.py on Host PC (for VM1→VM2 execution)")
    parser.add_argument("--elk_sender", default="elk_sender.py", help="Path to elk_sender.py on Host PC (to be uploaded to VM1)")
    parser.add_argument("--file_transfer", default="file_transfer.py", help="Path to file_transfer.py on Host PC")
    args = parser.parse_args()


    # 2) Prepare VM1 SSH config
    vm1_config = SSHClientManager(hostname=HOST, username=USER, password=PASSWORD)

    # 3) Check/install dependencies on VM1 using the default python interpreter
    vm1_config.ensure_python_module_dependencies()

    # 4) Transfer main file from Host → VM1
    logging.info("Transferring main file from Host to VM1...")
    remote_file_path = os.path.join(SAVING_PATH, os.path.basename(args.file))
    vm1_config.file_transfer(args.file, remote_file_path)

    logging.info(f"Main file transferred to VM1 at: {remote_file_path}")

    # 5) Ensure VM1 temporary directory exists
    vm1_temp_dir = VM1_TEMP_DIR
    vm1_config.execute_command(f'mkdir -p {vm1_temp_dir}')

    # 6) Always upload vm1_to_vm2.py, elk_sender.py, file_transfer.py, config.yaml to VM1
    remote_script = os.path.join(vm1_temp_dir, os.path.basename(args.script))
    remote_elk_sender = os.path.join(vm1_temp_dir, os.path.basename(args.elk_sender))
    remote_config_path = os.path.join(vm1_temp_dir, os.path.basename(args.config))
    remote_file_transfer = os.path.join(vm1_temp_dir, os.path.basename(args.file_transfer))

    logging.info(f"Uploading vm1_to_vm2.py to {remote_script}")
    vm1_config.execute_command(args.script, remote_script)

    logging.info(f"Uploading elk_sender.py to {remote_elk_sender}")
    vm1_config.execute_command(args.elk_sender, remote_elk_sender)

    logging.info(f"Uploading config to {remote_config_path}")
    vm1_config.execute_command(args.config, remote_config_path)

    logging.info(f"Uploading file_transfer.py to {remote_file_transfer}")
    vm1_config.execute_command(args.file_transfer, remote_file_transfer)

    # 7) Run vm1_to_vm2.py on VM1 using the default python interpreter.
    # vm1_to_vm2.py expects: local_file [--config CONFIG]
    command = f"{remote_script} {remote_file_path} --config {remote_config_path}"
    vm1_config.execute_command(f"python3 {command}")
    # python3 vm1_to_vm2.py **--file** <파일> --config config.yaml
if __name__ == "__main__":
    main()
