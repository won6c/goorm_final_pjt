import json
from CONFIG.config import IDENTIFY_OUTPUT_PATH, SIGNATURES, THRESHOLD

def classify_api_calls(api_list, signatures=SIGNATURES):
    match_counts = {mal_type: 0 for mal_type in signatures}
    for api in api_list:
        for mal_type, sig_set in signatures.items():
            if any(sig.lower() in api.lower() for sig in sig_set):
                match_counts[mal_type] += 1
                #break 
    if all(count == 0 for count in match_counts.values()):
        return "Unknown", match_counts
    else:
        classified_type = max(match_counts, key=match_counts.get)
        return classified_type, match_counts

def classify_threads(result_dict_copy):
    threads = result_dict_copy.get("process_frida", {}).get("threads", {})
    for tid, thread_info in threads.items():
        events = thread_info.get("events", [])
        api_list = []
        for event in events:
            if event.get("type") == "ThreadCall":
                target = event.get("target")
                if target:
                    try:
                        count = int(event.get("count", 1))
                    except Exception:
                        count = 1
                    api_list.extend([target] * count)
        thread_info["function or api"] = api_list
        classified_type, counts = classify_api_calls(api_list)
        thread_info["classification"] = {
            "malware_type": classified_type,
            "match_counts": counts
        }
    return result_dict_copy

def aggregate_classification(result_deep_copy):
    threads = result_deep_copy.get("process_frida", {}).get("threads", {})
    overall_counts = {mal_type: 0 for mal_type in SIGNATURES}
    for tid, thread_info in threads.items():
        classification = thread_info.get("classification", {})
        match_counts = classification.get("match_counts", {})
        for mal_type, count in match_counts.items():
            overall_counts[mal_type] += count
    return overall_counts

def final_classification(result_deep_copy):
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