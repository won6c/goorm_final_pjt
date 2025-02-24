import os
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--config", default=r"visualize\transfer\vm1_to_vm2.py", help="Path to the configuration file (default: config.yaml)")
args = parser.parse_args()

# 절대 경로로 변환
config_abs_path = os.path.abspath(args.config)

print(f"Config file absolute path: {config_abs_path}")
with open(config_abs_path, 'r', encoding='UTF-8') as file:
    print(file.read())
