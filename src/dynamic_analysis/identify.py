import json
from CONFIG.config import IDENTIFY_OUTPUT_PATH, SIGNATURES, THRESHOLD

def classify_api_calls(api_list, signatures=SIGNATURES):
    """
    입력된 API 리스트(api_list)를 기반으로, 각 악성코드 유형별 시그니처와의
    매칭 건수를 계산하여 가장 높은 건수를 가진 유형과 매칭 정보를 반환합니다.
    모든 매칭 건수가 0이면 "Unknown"을 반환합니다.
    """
    match_counts = {mal_type: 0 for mal_type in signatures}
    for api in api_list:
        for mal_type, sig_set in signatures.items():
            # 대소문자 무시 비교
            if any(sig.lower() in api.lower() for sig in sig_set):
                match_counts[mal_type] += 1
                #break  # 한 API는 한 유형에만 카운트
    if all(count == 0 for count in match_counts.values()):
        return "Unknown", match_counts
    else:
        classified_type = max(match_counts, key=match_counts.get)
        return classified_type, match_counts

def classify_threads(result_dict_copy):
    """
    result_dict_copy["process_frida"]["threads"]에 있는 각 스레드에 대해,
    "events" 항목에서 "ThreadCall" 이벤트의 "target"과 "count" 필드를 이용해
    API 호출 목록을 구성한 후, classify_api_calls()를 통해 분류 결과를 저장합니다.
    """
    threads = result_dict_copy.get("process_frida", {}).get("threads", {})
    for tid, thread_info in threads.items():
        events = thread_info.get("events", [])
        api_list = []
        for event in events:
            if event.get("type") == "ThreadCall":
                target = event.get("target")
                if target:
                    # count 필드가 있으면 해당 수만큼 추가, 없으면 1회 추가
                    try:
                        count = int(event.get("count", 1))
                    except Exception:
                        count = 1
                    api_list.extend([target] * count)
        # 저장 (나중에 재분석을 위해 "function or api" 필드에 저장)
        thread_info["function or api"] = api_list
        classified_type, counts = classify_api_calls(api_list)
        thread_info["classification"] = {
            "malware_type": classified_type,
            "match_counts": counts
        }
    return result_dict_copy

def aggregate_classification(result_deep_copy):
    """
    result_deep_copy["process_frida"]["threads"]에 저장된 각 스레드의
    "classification"의 "match_counts"를 모두 집계하여 전체 악성코드 유형별 매칭 건수를 반환합니다.
    """
    threads = result_deep_copy.get("process_frida", {}).get("threads", {})
    overall_counts = {mal_type: 0 for mal_type in SIGNATURES}
    for tid, thread_info in threads.items():
        classification = thread_info.get("classification", {})
        match_counts = classification.get("match_counts", {})
        for mal_type, count in match_counts.items():
            overall_counts[mal_type] += count
    return overall_counts

def final_classification(result_deep_copy):
    """
    각 스레드의 분류 결과를 종합하여 최종 악성코드 유형을 결정합니다.
    만약 전체 매칭 건수가 모두 0이거나 최대 매칭 건수가 THRESHOLD 미만이면 "Not Malware"로 분류합니다.
    """
    overall_counts = aggregate_classification(result_deep_copy)
    max_count = max(overall_counts.values()) if overall_counts else 0
    if max_count < THRESHOLD:
        final_type = "Not Malware"
    else:
        final_type = max(overall_counts, key=overall_counts.get)
    return final_type, overall_counts

def print_final_classification(result_deep_copy):
    final_type, overall_counts = final_classification(result_deep_copy)
    return final_type

def set_list(updated_result):
    threads = updated_result.get("process_frida", {}).get("threads", {})
    for tid, thread_info in threads.items():
        be_list = list(set(thread_info.get("function or api",{})))
        thread_info["function or api"]=be_list

def print_result(result_dict_copy):
    updated_result = classify_threads(result_dict_copy)
    set_list(updated_result)
    with open(IDENTIFY_OUTPUT_PATH, "w", encoding='utf-8') as f:
        json.dump(updated_result, f, indent=4, ensure_ascii=False)
    return print_final_classification(updated_result)