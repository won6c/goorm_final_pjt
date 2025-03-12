#!/usr/bin/env python3
import logging
import json
import sys, os
from datetime import datetime
from CONFIG.config import AWS_IP, ELASTICSEARCH_URL, INDEX_NAME
from elasticsearch import Elasticsearch

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def send_json_to_elk(json_file_path):
    """Read JSON file and indexing Elasticsearch"""
    try:
        es = Elasticsearch(ELASTICSEARCH_URL)
        logging.info(f'Elasticsearch URL: {ELASTICSEARCH_URL}')
    except Exception as e:
        logging.error(f'Error in creating lasticsearch client: [{e}]')
        return

    docs = json_file_path

    try:
        headers = {'Content-Type': 'application/json'}
        mapping = {
          "mappings": {
            "properties": {
              "static_analysis": {
                "type": "object",
                "properties": {
                  "pe_analysis": {
                    "type": "object",
                    "properties": {
                      "file_type": {
                        "type": "object",
                        "properties": {
                          "file": {
                            "type": "keyword"
                          },
                          "mime_type": {
                            "type": "keyword"
                          }
                        }
                      },
                      "sections": {
                        "type": "nested",
                        "properties": {
                          "section_name": {
                            "type": "keyword"
                          },
                          "entropy": {
                            "type": "keyword"
                          }
                        }
                      },
                      "hashes": {
                        "type": "object",
                        "properties": {
                          "MD5": {
                            "type": "keyword"
                          },
                          "SHA1": {
                            "type": "keyword"
                          },
                          "SHA256": {
                            "type": "keyword"
                          }
                        }
                      },
                      "pe_signature": {
                        "type": "object"
                      },
                      "imported_libraries": {
                        "type": "object"
                      },
                      "vt_result": {
                        "type": "object",
                        "properties": {
                          "Malicious_Engines": {
                            "type": "nested",
                            "properties": {
                              "engine": {
                                "type": "keyword"
                              },
                              "result": {
                                "type": "keyword"
                              }
                            }
                          },
                          "Suspicious_Engines": {
                            "type": "nested",
                            "properties": {
                              "engine": {
                                "type": "keyword"
                              },
                              "result": {
                                "type": "keyword"
                              }
                            }
                          }
                        }
                      },
                      "llm":{
                          "type":"object",
                          "properties":{
                              "probability":{
                                "type":"keyword"  
                              },
                              "result":{
                                  "type":"keyword"
                              }
                          }
                      }
                    }
                  }
                }
              },
              "dynamic_analysis": {
                "properties": {
                  "process_frida": {
                    "properties": {
                      "process": {
                        "type": "object",
                        "dynamic": False,
                        "properties": {
                          "pid": {
                            "type": "integer"
                          }
                        }
                      },
                      "threads": {
                        "type": "object",
                        "dynamic": True,
                      }
                    }
                  },
                  "process_dll": {
                    "type": "keyword",
                  },
                  "event_security": {
                    "type": "object",
                    "dynamic": True,
                  },
                  "event_system": {
                    "type": "object",
                    "dynamic": True,
                  },
                  "network_traffic": {
                      "type": "object",
                      "dynamic": True,
                    },
                  "reg": {
                    "properties": {
                      "added": {
                        "type": "object",
                        "dynamic": True,
                      },
                      "modified": {
                        "type": "object",
                        "dynamic": True,
                      },
                      "deleted": {
                        "type": "object",
                        "dynamic": True,
                      }
                    }
                  }
                }
              }
            }
          }
        }

        
        # 인덱스 생성
        index_name = INDEX_NAME.replace('*', datetime.now().strftime('%Y.%m.%d'))
        if not es.indices.exists(index=index_name):
            es.indices.create(index=index_name, body=mapping)
        response = es.index(index=index_name, document=docs, headers=headers)
        logging.info(f'Index docs successfully. index(Korean time): [{index_name}]')
        logging.info(f'Response info: [{response}]')
    except Exception as e:
        logging.error(f'Error in indexing Elasticsearch: [{e}]')
