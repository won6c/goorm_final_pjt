#!/usr/bin/env python3
import os
import json
import requests
import yaml
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class Visualization:
    def __init__(self, config_file="config.yaml"):
        # 설정 파일 로드
        self.config = self.load_config(config_file)
        # Kibana / Elasticsearch 설정
        self.KIBANA_URL = self.config.get("kibana_url", "http://localhost:5601")
        self.HEADERS = self.config.get("headers", {"kbn-xsrf": "true", "Content-Type": "application/json"})
        self.INDEX_PATTERN_TITLE = self.config.get("index_pattern_title", "malware-analysis-*")
        self.DATA_VIEW_ID = self.config.get("data_view_id", "malware-data-view")
        self.INDEX_PATTERN = None  # 실제 get_data_view_id() 로드 후 반영

    def load_config(self, config_file):
        """Load config from YAML file."""
        if not os.path.exists(config_file):
            logging.warning(f"Config file not found: {config_file}")
            return {}
        with open(config_file, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def create_data_view(self):
        """Create Kibana Data View."""
        url = f"{self.KIBANA_URL}/api/data_views/data_view"
        payload = {
            "data_view": {
                "title": self.INDEX_PATTERN_TITLE,
                "timeFieldName": "@timestamp"
            }
        }
        response = requests.post(url, headers=self.HEADERS, json=payload)
        if response.status_code in (200, 201):
            logging.info("Data view created successfully.")
        elif response.status_code == 409:
            logging.info("Data view already exists.")
        else:
            logging.error(f"Error creating data view: {response.status_code} {response.text}")

        # 실제 데이터 뷰 고유 ID를 가져옴
        self.INDEX_PATTERN = self.get_data_view_id()
        if self.INDEX_PATTERN:
            logging.info(f"Using data view ID: {self.INDEX_PATTERN}")
        else:
            logging.error("Could not retrieve data view ID.")

    def get_data_view_id(self):
        """Get actual data_view ID from Kibana."""
        url = f"{self.KIBANA_URL}/api/data_views"
        response = requests.get(url, headers=self.HEADERS)
        if response.status_code == 200:
            data_views = response.json().get("data_view", [])
            for view in data_views:
                if view.get("title") == self.INDEX_PATTERN_TITLE:
                    return view["id"]
        logging.error(f"Data view '{self.INDEX_PATTERN_TITLE}' not found.")
        return None

    def create_table_visualization(self, vis_id, title, agg_definitions, description=""):
        """Create a table visualization in Kibana."""
        if not self.INDEX_PATTERN:
            logging.error("INDEX_PATTERN is None. Data view must be created or retrieved first.")
            return

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
                        "index": self.INDEX_PATTERN,
                        "query": {"query": "", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        }
        resp = requests.post(url, headers=self.HEADERS, data=json.dumps(payload))
        if resp.status_code in (200, 201):
            logging.info(f"Table visualization '{vis_id}' created successfully.")
        else:
            logging.error(f"Error creating table visualization '{vis_id}': {resp.status_code} {resp.text}")

    def create_line_chart_visualization(self, vis_id, title):
        """Create a line chart visualization in Kibana."""
        if not self.INDEX_PATTERN:
            logging.error("INDEX_PATTERN is None. Data view must be created or retrieved first.")
            return

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
                        "min_doc_count": 1
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
                "description": "Dynamic events timeline",
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": self.INDEX_PATTERN,
                        "query": {"query": "", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        }
        resp = requests.post(url, headers=self.HEADERS, data=json.dumps(payload))
        if resp.status_code in (200, 201):
            logging.info(f"Line chart visualization '{vis_id}' created successfully.")
        else:
            logging.error(f"Error creating line chart visualization '{vis_id}': {resp.status_code} {resp.text}")

    def create_dashboard(self):
        """Create or update the 'malware-analysis-dashboard' dashboard."""
        dashboard_id = "malware-analysis-dashboard"
        url = f"{self.KIBANA_URL}/api/saved_objects/dashboard/{dashboard_id}"
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
            logging.info("Dashboard created successfully:")
            logging.info(response.json())
        elif response.status_code == 409:
            logging.info(f"Dashboard '{dashboard_id}' already exists. Trying to update.")
            response = requests.put(url, headers=self.HEADERS, data=json.dumps(dashboard_payload))
            if response.status_code in (200, 201):
                logging.info(f"Dashboard '{dashboard_id}' updated successfully.")
            else:
                logging.error(f"Error updating dashboard '{dashboard_id}': {response.status_code} {response.text}")
        else:
            logging.error(f"Error creating dashboard: {response.status_code} {response.text}")

    def build_dashboard(self):
        """Perform the entire sequence of building the dashboard: create data view, create visualizations, create dashboard."""
        self.create_data_view()

        # 예시: A1 (File / Hash / Score) 테이블
        agg_table_A1 = [
            {"id": "1", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "file_info.file_name.keyword", "size": 1}},
            {"id": "2", "enabled": True, "type": "avg", "schema": "metric", "params": {"field": "file_info.file_size"}},
            {"id": "3", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "file_info.md5.keyword", "size": 1}},
            {"id": "4", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "detection_result.keyword", "size": 1}}
        ]
        self.create_table_visualization(
            vis_id="sectionA1-viz",
            title="Section A - A1: File / Hash / Score",
            agg_definitions=agg_table_A1,
            description="Shows basic file info"
        )

        # 필요에 따라 다른 테이블/라인 차트 시각화도 추가
        # 예: self.create_line_chart_visualization("sectionC1-viz", "Section C - C1: Process Activity")

        # 마지막에 대시보드 생성
        self.create_dashboard()

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Set up Kibana dashboard using config.yaml")
    parser.add_argument("--config", default="config.yaml", help="Path to config file")
    args = parser.parse_args()

    visualization = Visualization(config_file=args.config)
    visualization.build_dashboard()

if __name__ == "__main__":
    main()
