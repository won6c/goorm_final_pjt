from elasticsearch import Elasticsearch
from datetime import datetime
import pytz
import requests
import json
import os

class ELK:
    def __init__(self):
        # 변경필요: 환경에 맞게 인덱스 이름, Kibana URL, Elasticsearch URL 등을 수정하세요.
        self.INDEX_NAME = "malware-analysis-" + datetime.now(pytz.utc).strftime("%Y.%m.%d")
        self.KIBANA_URL = "http://3.36.50.236:5601"
        self.ELASTICSEARCH_URL = "http://3.36.50.236:9200"
        self.HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}
        self.INDEX_PATTERN_TITLE = "malware-analysis-*"
        self.DATA_VIEW_ID = "malware-data-view"
        self.panel_idx = 1
        self.INDEX_PATTERN = None  # 이후, 실제 데이터 뷰 고유 ID로 할당

    def init_elk(self):
        self.es = Elasticsearch(self.ELASTICSEARCH_URL)

    def load_json_file(self, file_path):
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            return None
        with open(file_path, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except Exception as e:
                print(f"Error reading {file_path}: {e}")
                return None

    def index_analysis_data(self, static_file="static_analysis.json", dynamic_file="dynamic_analysis.json"):
        static_doc = self.load_json_file(static_file)
        dynamic_doc = self.load_json_file(dynamic_file)
        if static_doc is None or dynamic_doc is None:
            print("Error: Could not load analysis JSON files.")
            return
        try:
            self.es.index(index=self.INDEX_NAME, document=static_doc)
            self.es.index(index=self.INDEX_NAME, document=dynamic_doc)
            print("Data indexed successfully into index:", self.INDEX_NAME)
        except Exception as e:
            print("Error indexing documents:", e)

    # 데이터 뷰 생성 (Kibana 8.x 기준)
    def create_data_view(self):
        url = f"{self.KIBANA_URL}/api/data_views/data_view"
        payload = {
            "data_view": {
                "title": self.INDEX_PATTERN_TITLE,
                "timeFieldName": "@timestamp"
            }
        }
        response = requests.post(url, headers=self.HEADERS, json=payload)
        if response.status_code in (200, 201):
            print("Data view created successfully.")
        elif response.status_code == 409:
            print("Data view already exists.")
        else:
            print(f"Error creating data view: {response.status_code} {response.text}")
        # 데이터 뷰 생성 후, 실제 고유 ID를 가져와 self.INDEX_PATTERN에 할당합니다.
        self.INDEX_PATTERN = self.get_data_view_id()
        if self.INDEX_PATTERN:
            print(f"Using data view ID: {self.INDEX_PATTERN}")
        else:
            print("Error: Could not retrieve data view ID.")

    # 데이터 뷰 실제 고유 ID 조회 함수
    def get_data_view_id(self):
        url = f"{self.KIBANA_URL}/api/data_views"
        response = requests.get(url, headers=self.HEADERS)
        if response.status_code == 200:
            data_views = response.json().get("data_view", [])
            for view in data_views:
                if view.get("title") == self.INDEX_PATTERN_TITLE:
                    return view["id"]
        print(f"Data view '{self.INDEX_PATTERN_TITLE}' not found.")
        return None

    # 공통: Table 시각화 생성 함수 (POST 사용)
    def create_table_visualization(self, vis_id, title, index_pattern, agg_definitions, description=""):
        url = f"{self.KIBANA_URL}/api/saved_objects/visualization/{vis_id}"
        vis_state = {
            "title": title,
            "type": "table",
            "params": {
                "perPage": 10,
                "showPartialRows": False,
                "showTotal": True
            },
            "aggs": agg_definitions
        }
        payload = {
            "attributes": {
                "title": title,
                "visState": json.dumps(vis_state),
                "uiStateJSON": "{}",
                "description": description,
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": index_pattern,   # 여기서 index_pattern은 실제 데이터 뷰의 고유 ID이어야 합니다.
                        "query": {"query": "", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        }
        response = requests.post(url, headers=self.HEADERS, data=json.dumps(payload))
        if response.status_code in (200, 201):
            print(f"Table visualization '{vis_id}' created successfully.")
        else:
            print(f"Error creating table visualization '{vis_id}': {response.status_code} {response.text}")

    # 공통: Line 차트 시각화 생성 함수 (POST 사용)
    def create_line_chart_visualization(self, vis_id, title, index_pattern):
        url = f"{self.KIBANA_URL}/api/saved_objects/visualization/{vis_id}"
        vis_state = {
            "title": title,
            "type": "line",
            "params": {
                "shareYAxis": True,
                "addTooltip": True,
                "addLegend": True,
                "showCircles": True,
                "smoothLines": False,
                "interpolate": "linear",
                "scale": "linear"
            },
            "aggs": [
                {
                    "id": "1",
                    "enabled": True,
                    "type": "date_histogram",
                    "schema": "segment",
                    "params": {
                        "field": "@timestamp",
                        "interval": "auto",
                        "min_doc_count": 1,
                        "extended_bounds": {}
                    }
                },
                {
                    "id": "2",
                    "enabled": True,
                    "type": "count",
                    "schema": "metric",
                    "params": {}
                }
            ]
        }
        payload = {
            "attributes": {
                "title": title,
                "visState": json.dumps(vis_state),
                "uiStateJSON": "{}",
                "description": "Timeline of dynamic events",
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": index_pattern,
                        "query": {"query": "", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        }
        response = requests.post(url, headers=self.HEADERS, data=json.dumps(payload))
        if response.status_code in (200, 201):
            print(f"Line chart visualization '{vis_id}' created successfully.")
        else:
            print(f"Error creating line chart visualization '{vis_id}': {response.status_code} {response.text}")

    # 대시보드 생성 함수 (POST 사용, 고정된 ID 사용)
    def create_dashboard(self):
        dashboard_id = "malware-analysis-dashboard"  # 고정된 대시보드 ID
        url = f"{self.KIBANA_URL}/api/saved_objects/dashboard/{dashboard_id}"
        # 패널 배열: Section A는 전체 너비(24), Section B는 3개(각 너비 8), Section C는 첫 줄에 3개(각 8) + 두번째 줄에 1개(전체 너비 24)
        panels = [
            {"panelIndex": "1", "gridData": {"x": 0, "y": 0, "w": 48, "h": 8, "i": "1"}, "version": "8.15.1", "panelRefName": "panel_A1"},
            {"panelIndex": "2", "gridData": {"x": 0, "y": 8, "w": 16, "h": 8, "i": "2"}, "version": "8.15.1", "panelRefName": "panel_B1"},
            {"panelIndex": "3", "gridData": {"x": 16, "y": 8, "w": 16, "h": 8, "i": "3"}, "version": "8.15.1", "panelRefName": "panel_B2"},
            {"panelIndex": "4", "gridData": {"x": 32, "y": 8, "w": 16, "h": 8, "i": "4"}, "version": "8.15.1", "panelRefName": "panel_B3"},
            {"panelIndex": "5", "gridData": {"x": 0, "y": 16, "w": 16, "h": 8, "i": "5"}, "version": "8.15.1", "panelRefName": "panel_C1"},
            {"panelIndex": "6", "gridData": {"x": 16, "y": 16, "w": 16, "h": 8, "i": "6"}, "version": "8.15.1", "panelRefName": "panel_C2"},
            {"panelIndex": "7", "gridData": {"x": 32, "y": 16, "w": 16, "h": 8, "i": "7"}, "version": "8.15.1", "panelRefName": "panel_C3"},
            {"panelIndex": "8", "gridData": {"x": 0, "y": 24, "w": 48, "h": 8, "i": "8"}, "version": "8.15.1", "panelRefName": "panel_C4"}
        ]
        dashboard_payload = {
            "attributes": {
                "title": "Malware Analysis Dashboard",
                "panelsJSON": json.dumps(panels),
                "optionsJSON": "{\"darkTheme\":false}",
                "version": 1,
                "timeRestore": False,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": "{\"filter\":[]}"
                }
            },
            "references": [
                {"id": "sectionA1-viz", "name": "panel_A1", "type": "visualization"},
                {"id": "sectionB1-viz", "name": "panel_B1", "type": "visualization"},
                {"id": "sectionB2-viz", "name": "panel_B2", "type": "visualization"},
                {"id": "sectionB3-viz", "name": "panel_B3", "type": "visualization"},
                {"id": "sectionC1-viz", "name": "panel_C1", "type": "visualization"},
                {"id": "sectionC2-viz", "name": "panel_C2", "type": "visualization"},
                {"id": "sectionC3-viz", "name": "panel_C3", "type": "visualization"},
                {"id": "sectionC4-viz", "name": "panel_C4", "type": "visualization"}
            ]
        }
        response = requests.post(url, headers=self.HEADERS, data=json.dumps(dashboard_payload))
        if response.status_code in (200, 201):
            print("Dashboard created successfully:")
            print(json.dumps(response.json(), indent=2))
        elif response.status_code == 409:
            print(f"Dashboard '{dashboard_id}' already exists. Updating existing dashboard.")
            response = requests.put(url, headers=self.HEADERS, data=json.dumps(dashboard_payload))
            if response.status_code in (200, 201):
                print(f"Dashboard '{dashboard_id}' updated successfully.")
            else:
                print(f"Error updating dashboard '{dashboard_id}': {response.status_code} {response.text}")
        else:
            print(f"Error creating dashboard: {response.status_code} {response.text}")

    def process(self):
        self.init_elk()
        self.index_analysis_data()  # 정적/동적 분석 산출물 JSON 파일 색인 (필요시 파일 경로 수정)
        self.create_data_view()       # Kibana 데이터 뷰 생성 및 self.INDEX_PATTERN 업데이트
        # Section A: A1 - File / Hash / Score (Table)
        agg_table_A1 = [
            {"id": "1", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "file_info.file_name.keyword", "size": 1}},
            {"id": "2", "enabled": True, "type": "avg", "schema": "metric", "params": {"field": "file_info.file_size"}},
            {"id": "3", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "file_info.md5.keyword", "size": 1}},
            {"id": "4", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "detection_result.keyword", "size": 1}}
        ]
        self.create_table_visualization("sectionA1-viz", "Section A - A1: File / Hash / Score", self.INDEX_PATTERN, agg_table_A1)
        
        # Section B:
        # B1: File Type & Imported Libraries (Table)
        agg_table_B1 = [
            {"id": "1", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "file_info.file_type.keyword", "size": 1}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "imported_libraries.keyword", "size": 10}}
        ]
        self.create_table_visualization("sectionB1-viz", "Section B - B1: File Type & Libraries", self.INDEX_PATTERN, agg_table_B1)
        # B2: Yara Rules & Embedded Strings (Table)
        agg_table_B2 = [
            {"id": "1", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "yara_rules.keyword", "size": 10}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "embedded_strings.keyword", "size": 10}}
        ]
        self.create_table_visualization("sectionB2-viz", "Section B - B2: Yara Rules & Embedded Strings", self.INDEX_PATTERN, agg_table_B2)
        # B3: PE Section / Signature (Table)
        agg_table_B3 = [
            {"id": "1", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "parsed_sections.name.keyword", "size": 5}},
            {"id": "2", "enabled": True, "type": "avg", "schema": "metric", "params": {"field": "parsed_sections.raw_size"}}
        ]
        self.create_table_visualization("sectionB3-viz", "Section B - B3: PE Section / Signature", self.INDEX_PATTERN, agg_table_B3)
        
        # Section C:
        # C1: Process Activity (Line Chart)
        self.create_line_chart_visualization("sectionC1-viz", "Section C - C1: Process Activity", self.INDEX_PATTERN)
        # C2: File System Changes (Table)
        agg_table_C2 = [
            {"id": "1", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "file_changes.created_files.keyword", "size": 5}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "file_changes.deleted_files.keyword", "size": 5}}
        ]
        self.create_table_visualization("sectionC2-viz", "Section C - C2: File System Changes", self.INDEX_PATTERN, agg_table_C2, "Shows file creation and deletion events.")
        # C3: Network Traffic (Table)
        agg_table_C3 = [
            {"id": "1", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "network_traffic.c2_server.ip.keyword", "size": 1}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "network_events.destination_ip.keyword", "size": 5}}
        ]
        self.create_table_visualization("sectionC3-viz", "Section C - C3: Network Traffic", self.INDEX_PATTERN, agg_table_C3, "Shows network connection events.")
        # C4: Registry Changes (Table)
        agg_table_C4 = [
            {"id": "1", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "registry_changes.keyword", "size": 1}}
        ]
        self.create_table_visualization("sectionC4-viz", "Section C - C4: Registry Changes", self.INDEX_PATTERN, agg_table_C4, "Shows registry change events.")
        
        # 최종적으로 대시보드 생성
        self.create_dashboard()

if __name__ == "__main__":
    elk = ELK()
    elk.process()
