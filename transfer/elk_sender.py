# elk_sender.py
import logging
import requests
import yaml
import os

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def load_config(config_file: str):
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Config file not found: {config_file}")
    with open(config_file, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    if config is None:
        raise ValueError(f"Config file {config_file} is empty or invalid.")
    return config

def send_json_to_elk(json_file_path: str, config_file: str = "config.yaml"):
    """
    JSON 파일을 읽어, config_file에서 ELK 정보를 불러와 AWS ELK 엔드포인트로 HTTP POST 전송합니다.
    """
    config = load_config(config_file)
    elk_config = config.get("elk", {})
    elk_endpoint = elk_config.get("endpoint")
    headers = elk_config.get("headers", {"Content-Type": "application/json"})
    
    if not elk_endpoint:
        logging.error("ELK endpoint is not configured in the config file.")
        return

    try:
        with open(json_file_path, "r", encoding="utf-8") as f:
            json_data = f.read()
        response = requests.post(elk_endpoint, data=json_data, headers=headers)
        if response.status_code in (200, 201):
            logging.info("Successfully sent JSON analysis report to AWS ELK.")
        else:
            logging.error(f"Failed to send JSON to AWS ELK: {response.status_code} {response.text}")
    except Exception as e:
        logging.error(f"Error sending JSON to AWS ELK: {e}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Send JSON file to AWS ELK using configuration from a config file.")
    parser.add_argument("--file", required=True, help="Path to the JSON file to send")
    parser.add_argument("--config", default="config.yaml", help="Path to the config file (default: config.yaml)")
    args = parser.parse_args()
    send_json_to_elk(args.file, config_file=args.config)
