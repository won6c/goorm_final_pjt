import win32evtlog
import win32evtlogutil
import win32con
import datetime
import logging
from dynamic_analysis.common import stop_event

# 로그 저장 설정
#logging.basicConfig(filename="system_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

def log_event(event_id, event_time, event_source, event_message):
    """이벤트 정보를 로그 파일에 저장"""
    log_message = f"[EVENT] ID: {event_id} | Time: {event_time} | Provider: {event_source} | Message: {event_message}"
    logging.info(log_message)
    #print(f" [LOGGED] {log_message}")
    return {"event_id":event_id,"event_time":event_time,"event_provider":event_source,"event_message":event_message}

def monitor_system_event_log(server="localhost", log_type="System", event_id_filter=None):
    """Windows 이벤트 로그 모니터링"""
    hand = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    #print(f"[INFO] Monitoring {log_type} log...")
    result_dict = {}
    result_dict["system"]=[]

    while not stop_event.is_set():
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            break

        for event in events:
            event_id = event.EventID & 0xFFFF
            event_time = event.TimeGenerated.Format()
            event_source = event.SourceName

            # 이벤트 메시지 추출
            event_data = event.StringInserts
            event_message = " | ".join(event_data) if event_data else "No additional information"

            # 특정 이벤트 ID 필터링
            if event_id_filter and event_id not in event_id_filter:
                continue

            # 로그 파일에 저장
            result_dict["system"].append(log_event(event_id, event_time, event_source, event_message))

    win32evtlog.CloseEventLog(hand)

    return result_dict

