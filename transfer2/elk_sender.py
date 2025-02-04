# elk_sender.py
import logging
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def send_json_to_elk(json_file_path: str, elk_endpoint: str, headers: dict = None):
    """
    JSON 파일을 읽어 AWS ELK 엔드포인트로 HTTP POST 전송합니다.
    elk_endpoint: 예) "http://AWS_ELK_ENDPOINT:9200/your_index/_doc"
    headers: 기본값은 {"Content-Type": "application/json"}
    """
    if headers is None:
        headers = {"Content-Type": "application/json"}
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
