import json
import logging

import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

AWS_IP = '13.209.85.163'
KIBANA_URL = f'http://{AWS_IP}:5601'
ELASTICSEARCH_URL = f'http://{AWS_IP}:9200'

INDEX_NAME = 'malware-analysis'
INDEX_PATTERN_TITLE = 'malware-analysis' # 인덱스 패턴 제목 (Kibana 데이터 뷰 생성 시 사용)
DATA_VIEW_ID = 'malware-data-view' # 데이터 뷰 고유 ID (옵션 - 미리 정의된 ID가 있다면 사용, 없으면 빈 값으로 두세요)


class Visualization:
    def __init__(self):
        self.headers = {'kbn-xsrf': 'true', 'Content-Type': 'application/json'}
        self.data_view_id = DATA_VIEW_ID
        self.index_pattern = None  # 실제 get_data_view_id() 로드 후 반영

    def create_data_view(self):
        """Create Kibana Data View."""
        url = f'{KIBANA_URL}/api/data_views/data_view'
        payload = {
            "data_view": {
                "title": INDEX_PATTERN_TITLE,
                "timeFieldName": "@timestamp"
            }
        }
        response = requests.post(url, headers=self.headers, json=payload)
        if response.status_code in (200, 201):
            logging.info('✅ Data view created successfully.')
        elif response.status_code == 409:
            logging.info('⚠️ Data view already exists.')
        else:
            logging.error(f'❌ Error creating data view: {response.status_code} {response.text}')

    def get_data_view_id(self):
        """Get actual data_view ID from Kibana."""
        url = f'{KIBANA_URL}/api/data_views'
        response = requests.get(url, headers=self.headers)
        if response.status_code == 200:
            data_views = response.json().get('data_view', [])
            for view in data_views:
                if view.get('title') == INDEX_PATTERN_TITLE:
                    logging.info(f'✅ Using data view ID: {self.index_pattern}')
                    return view['id']
        logging.error(f'Data view "{INDEX_PATTERN_TITLE}" not found.')
        return None

    def create_table_visualization(self, vis_id, title, agg_definitions, description=''):
        """Create a table visualization in Kibana."""
        if not self.index_pattern:
            logging.error('I❌ NDEX_PATTERN is None. Data view must be created or retrieved first.')
            return

        url = f'{KIBANA_URL}/api/saved_objects/visualization/{vis_id}'
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
                        "index": self.index_pattern,
                        "query": {"query": "", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        }
        resp = requests.post(url, headers=self.headers, data=json.dumps(payload))
        if resp.status_code in (200, 201):
            logging.info(f'Table visualization "{vis_id}" created successfully.')
        else:
            logging.error(f'Error creating table visualization "{vis_id}": {resp.status_code} {resp.text}')

    def create_line_chart_visualization(self, vis_id, title):
        """Create a line chart visualization in Kibana."""
        if not self.index_pattern:
            logging.error('INDEX_PATTERN is None. Data view must be created or retrieved first.')
            return

        url = f'{KIBANA_URL}/api/saved_objects/visualization/{vis_id}'
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
                        "index": self.index_pattern,
                        "query": {"query": "", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        }
        resp = requests.post(url, headers=self.headers, data=json.dumps(payload))
        if resp.status_code in (200, 201):
            logging.info(f'Line chart visualization "{vis_id}" created successfully.')
        else:
            logging.error(f'Error creating line chart visualization "{vis_id}": {resp.status_code} {resp.text}')

    def create_dashboard(self):
        """Create or update the 'malware-analysis-dashboard' dashboard."""
        dashboard_id = 'malware-analysis-dashboard'
        url = f'{KIBANA_URL}/api/saved_objects/dashboard/{dashboard_id}'
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
        response = requests.post(url, headers=self.headers, data=json.dumps(dashboard_payload))
        if response.status_code in (200, 201):
            logging.info('Dashboard created successfully:')
            logging.info(response.json())
        elif response.status_code == 409:
            logging.info(f'Dashboard "{dashboard_id}" already exists. Trying to update.')
            response = requests.put(url, headers=self.headers, data=json.dumps(dashboard_payload))
            if response.status_code in (200, 201):
                logging.info(f'Dashboard "{dashboard_id}" updated successfully.')
            else:
                logging.error(f'Error updating dashboard "{dashboard_id}": {response.status_code} {response.text}')
        else:
            logging.error(f'Error creating dashboard: {response.status_code} {response.text}')

    def build_dashboard(self):
        """Perform the entire sequence of building the dashboard: create data view, create visualizations, create dashboard."""
        self.create_data_view()
        
        # 실제 데이터 뷰 고유 ID를 가져옴
        self.index_pattern = self.get_data_view_id()

        # 예시: A1 (File / Hash / Score) 테이블
        agg_table_A1 = [
            {"id": "1", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "file_info.file_name.keyword", "size": 1}},
            {"id": "2", "enabled": True, "type": "avg", "schema": "metric", "params": {"field": "file_info.file_size"}},
            {"id": "3", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "file_info.md5.keyword", "size": 1}},
            {"id": "4", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "detection_result.keyword", "size": 1}}
        ]
        self.create_table_visualization(
            vis_id='sectionA1-viz',
            title='Section A - A1: File / Hash / Score',
            agg_definitions=agg_table_A1,
            description='Shows basic file info'
        )

        # 필요에 따라 다른 테이블/라인 차트 시각화도 추가
        # 예: self.create_line_chart_visualization('sectionC1-viz', 'Section C - C1: Process Activity')

        # 마지막에 대시보드 생성
        self.create_dashboard()

def main():
    visualization = Visualization()
    visualization.build_dashboard()

if __name__ == '__main__':
    main()
