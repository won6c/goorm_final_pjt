#!/usr/bin/env python3
import logging
import json
import sys
from datetime import datetime

from elasticsearch import Elasticsearch

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

AWS_IP = '43.202.46.253'
ELASTICSEARCH_URL = f'http://{AWS_IP}:9200'
KIBANA_URL = f'http://{AWS_IP}:5601'

INDEX_NAME = 'malware-analysis-*'


def send_json_to_elk(json_file_path: str):
    """Read JSON file and indexing Elasticsearch"""
    try:
        es = Elasticsearch(ELASTICSEARCH_URL)
        logging.info(f'Elasticsearch URL: {ELASTICSEARCH_URL}')
    except Exception as e:
        logging.error(f'Error in creating lasticsearch client: [{e}]')
        return

    try:
        with open(json_file_path, 'r', encoding='utf-8') as file:
            docs = json.load(file)
    except Exception as e:
        logging.error(f'Error in loading "{json_file_path}" JSON file: [{e}]')
        return

    try:
        headers = {'Content-Type': 'application/json'}
        index_name = INDEX_NAME.replace('*', datetime.now().strftime('%Y.%m.%d'))
        response = es.index(index=index_name, document=docs, headers=headers)
        logging.info(f'Index docs successfully. index(Korean time): [{index_name}]')
        logging.info(f'Response info: [{response}]')
    except Exception as e:
        logging.error(f'Error in indexing Elasticsearch: [{e}]')

def main():
    if len(sys.argv) < 2:
        logging.error('Usage: python elk_sender.py <json_file>')
        sys.exit(1)
    send_json_to_elk(sys.argv[1])

if __name__ == '__main__':
    main()
