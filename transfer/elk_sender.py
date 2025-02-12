#!/usr/bin/env python3
import logging
import yaml
import json
import sys
from elasticsearch import Elasticsearch
from datetime import datetime
import pytz

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def load_config(config_file="config.yaml"):
    """
    YAML 형식의 설정 파일을 읽어 딕셔너리로 반환합니다.
    """
    try:
        with open(config_file, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
            return config
    except Exception as e:
        logging.error(f"설정 파일 '{config_file}' 로드 중 오류 발생: {e}")
        sys.exit(1)

def send_json_to_elk(json_file_path: str, config_file: str = "config.yaml"):
    """
    JSON 파일을 읽어 Elasticsearch에 색인(index)합니다.
    모든 접속 정보 및 인덱스 관련 설정은 config.yaml 에서 읽어옵니다.
    """
    config = load_config(config_file)
    elk_config = config.get("elk", {})

    # Elasticsearch URL은 config.yaml의 elasticsearch_url 항목을 사용합니다.
    elasticsearch_url = elk_config.get("elasticsearch_url")
    if not elasticsearch_url:
        logging.error("config.yaml에 'elk.elasticsearch_url'이 정의되어 있지 않습니다.")
        sys.exit(1)
    logging.info(f"Elasticsearch URL: {elasticsearch_url}")

    headers = elk_config.get("headers", {"Content-Type": "application/json"})
    
    try:
        es = Elasticsearch(elasticsearch_url)
    except Exception as e:
        logging.error(f"Elasticsearch 클라이언트 생성 중 오류: {e}")
        sys.exit(1)
    
    # JSON 파일 읽기
    try:
        with open(json_file_path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except Exception as e:
        logging.error(f"JSON 파일 '{json_file_path}' 로드 중 오류: {e}")
        sys.exit(1)
    
    # 인덱스 이름 설정: config의 index_name 값을 읽어,
    # 만약 '*' 문자가 포함되어 있다면 현재 UTC 날짜(YYYY.MM.DD)로 치환합니다.
    base_index_name = elk_config.get("index_name")
    if not base_index_name:
        logging.error("config.yaml에 'elk.index_name'이 정의되어 있지 않습니다.")
        sys.exit(1)
    if "*" in base_index_name:
        date_str = datetime.now(pytz.utc).strftime("%Y.%m.%d")
        index_name = base_index_name.replace("*", date_str)
    else:
        index_name = base_index_name

    logging.info(f"문서를 색인할 인덱스 이름: {index_name}")

    try:
        response = es.index(index=index_name, document=doc, headers=headers)
        logging.info(f"문서가 성공적으로 색인되었습니다. 인덱스: {index_name}")
        logging.info(f"응답 내용: {response}")
    except Exception as e:
        logging.error(f"Elasticsearch 색인 중 오류 발생: {e}")
        sys.exit(1)

def main():
    if len(sys.argv) < 2:
        logging.error("사용법: python elk_sender.py <json_file> [config_file]")
        sys.exit(1)
    json_file_path = sys.argv[1]
    config_file = sys.argv[2] if len(sys.argv) >= 3 else "config.yaml"
    send_json_to_elk(json_file_path, config_file=config_file)

if __name__ == "__main__":
    main()
