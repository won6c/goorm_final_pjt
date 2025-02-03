import win32evtlog
import win32evtlogutil
import win32con
import datetime
import logging

# 로그 저장 설정
logging.basicConfig(filename="system_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

def log_event(event_id, event_time, event_source, event_message):
    """이벤트 정보를 로그 파일에 저장"""
    log_message = f"[EVENT] ID: {event_id} | Time: {event_time} | Provider: {event_source} | Message: {event_message}"
    logging.info(log_message)
    print(f" [LOGGED] {log_message}")

def monitor_event_log(server="localhost", log_type="System", event_id_filter=None):
    """Windows 이벤트 로그 모니터링"""
    hand = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    print(f"[INFO] Monitoring {log_type} log...")

    while True:
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

            print(f"\n[EVENT DETECTED] ID: {event_id}")
            print(f" - Time Generated: {event_time}")
            print(f" - Service Provider: {event_source}")
            print(f" - Event Message: {event_message}")

            # 로그 파일에 저장
            log_event(event_id, event_time, event_source, event_message)

    win32evtlog.CloseEventLog(hand)

if __name__ == "__main__":
    monitor_event_log(log_type="System", event_id_filter=[6005, 6006, 7001, 7036])

