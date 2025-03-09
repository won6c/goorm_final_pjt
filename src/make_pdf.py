import json
import logging
import time
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepInFrame
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from datetime import datetime
from elasticsearch import Elasticsearch

AWS_IP = '127.0.0.1'
ELASTICSEARCH_URL = f'http://{AWS_IP}:9200'
INDEX_NAME = f'04.exe-*'

def get_json_from_elk():
    while True:
        try:
            es = Elasticsearch(ELASTICSEARCH_URL)
            logging.info(f'Elasticsearch URL: {ELASTICSEARCH_URL}')
        except Exception as e:
            logging.error(f'Error creating Elasticsearch client: [{e}]')
            logging.info("Retrying in 30 seconds...")
            time.sleep(30)
            continue

        index_name = INDEX_NAME.replace('*', datetime.now().strftime('%Y.%m.%d'))
        try:
            res = es.search(index=index_name, body={"query": {"match_all": {}}})
            return res  # 성공하면 결과 반환하고 루프 종료
        except Exception as e:
            logging.error(f'Error in retrieving documents: [{e}]')
            logging.info("Retrying in 30 seconds...")
            time.sleep(30)

def get_suspicious_list(details):
    # Helper: return suspicious list if key contains 'suspicious' (case-insensitive)
    for key, value in details.items():
        if "suspicious" in key.lower():
            return value
    return []

def create_pdf_report(json_data, output_filename):
    doc = SimpleDocTemplate(output_filename, pagesize=letter,
                            rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    # 들여쓰기를 적용한 스타일 추가
    styles.add(ParagraphStyle(name='Heading1Indent', parent=styles['Heading1'], leftIndent=0))
    styles.add(ParagraphStyle(name='Heading2Indent', parent=styles['Heading2'], leftIndent=20))
    styles.add(ParagraphStyle(name='Heading3Indent', parent=styles['Heading3'], leftIndent=40))
    styles.add(ParagraphStyle(name='Heading4Indent', parent=styles['Heading4'], leftIndent=60))
    
    # 작은 글꼴 스타일 (본문)
    small_style = ParagraphStyle('small_style', parent=styles['BodyText'], fontSize=8, leading=10)

    story = []
    
    # Title (최상위, 들여쓰기 없음)
    story.append(Paragraph("Target Analysis Report", styles['Title']))
    story.append(Spacer(1, 0.3*inch))
    
    #############################
    # 1. Static Analysis Section
    #############################
    story.append(Paragraph("1. Static Analysis", styles['Heading1Indent']))
    
    # (1) File Info
    story.append(Paragraph("(1) File Info", styles['Heading2Indent']))
    static = json_data.get("StaticAnalysis", {})
    pe_analysis = static.get("pe_analysis", {})
    
    file_info_data = [["Field", "Value"]]
    infected_files = static.get("infected_files", [])
    target_file_path = infected_files[0] if infected_files else "N/A"
    file_info_data.append(["Target File Path", target_file_path])
    
    # Hashes: 각 해시를 개별 줄로 표시
    hashes = pe_analysis.get("hashes", [])
    if isinstance(hashes, list) and hashes:
        hash_lines = [f"{h.get('hash_type', 'N/A')}: {h.get('hash_value', 'N/A')}" for h in hashes]
        hash_str = "<br/>".join(hash_lines)
    else:
        hash_str = "N/A"
    hash_paragraph = Paragraph(hash_str, small_style)
    hash_cell = KeepInFrame(4*inch, 1*inch, [hash_paragraph], hAlign='LEFT', vAlign='MIDDLE')
    file_info_data.append(["Hashes", hash_cell])
    
    extension = pe_analysis.get("file_type", {}).get("extension", "N/A")
    file_info_data.append(["Extension", extension])
    mime_type = pe_analysis.get("file_type", {}).get("mime_type", "N/A")
    file_info_data.append(["MIME Type", mime_type])
    pe_signature = pe_analysis.get("pe_signature", {})
    pe_signature_str = "<br/>".join(f"{k}: {v}" for k, v in pe_signature.items()) if pe_signature else "N/A"
    pe_sig_paragraph = Paragraph(pe_signature_str, small_style)
    pe_sig_cell = KeepInFrame(4*inch, 1*inch, [pe_sig_paragraph], hAlign='LEFT', vAlign='MIDDLE')
    file_info_data.append(["PE Signature", pe_sig_cell])
    
    table_file_info = Table(file_info_data, colWidths=[2*inch, 4*inch])
    table_file_info.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.gray),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('GRID', (0,0), (-1,-1), 1, colors.black),
        ('VALIGN', (0,2), (-1,2), 'MIDDLE'),
        ('VALIGN', (0,5), (-1,5), 'MIDDLE'),
        ('FONTSIZE', (0,0), (-1,-1), 8),
    ]))
    story.append(table_file_info)
    story.append(Spacer(1, 0.3*inch))
    
    # (2) PE Analysis
    story.append(Paragraph("(2) PE Analysis", styles['Heading2Indent']))
    # (2)-1. Sections
    sections = pe_analysis.get("sections", [])
    if sections:
        sec_data = [["Section Name", "Size", "Entropy"]]
        for sec in sections:
            sec_data.append([sec.get("section_name", "N/A"), str(sec.get("size", "N/A")), str(sec.get("entropy", "N/A"))])
        table_sections = Table(sec_data, colWidths=[2*inch, 2*inch, 2*inch])
        table_sections.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.darkblue),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('FONTSIZE', (0,0), (-1,-1), 8),
        ]))
        story.append(Paragraph("1. Sections", styles['Heading3Indent']))
        story.append(table_sections)
        story.append(Spacer(1, 0.2*inch))
    
    # (2)-2. Imported Libraries
    imported_libraries = pe_analysis.get("imported_libraries", {})
    if imported_libraries:
        for lib, details in imported_libraries.items():
            story.append(Paragraph(f"Library: {lib}", styles['Heading3Indent']))
            suspicious = get_suspicious_list(details)
            functions = details.get("functions", [])
            n_rows = len(suspicious)
            if n_rows == 0:
                n_rows = 1
            table_rows = [["Suspicious Functions"]]
            for i in range(n_rows):
                susp_item = suspicious[i] if i < len(suspicious) else ""
                susp_par = Paragraph(f'<para align="center">{susp_item}</para>', small_style)
                table_rows.append([susp_par])
            table_lib = Table(table_rows, colWidths=[6*inch])
            table_lib.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.darkorange),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
                ('FONTSIZE', (0,0), (-1,-1), 8),
            ]))
            story.append(table_lib)
            story.append(Spacer(1, 0.2*inch))
    
    # (3) Virustotal Result
    vt_result = static.get("vt_result", {})
    if vt_result:
        story.append(Paragraph("(3) Virustotal Result", styles['Heading2Indent']))
        vt_data = [["Field", "Value"]]
        filenames = vt_result.get("Filenames", [])
        if filenames:
            filenames_str = "<br/>".join(filenames)
        else:
            filenames_str = "N/A"
        filenames_paragraph = Paragraph(filenames_str, small_style)
        filenames_cell = KeepInFrame(4*inch, 1*inch, [filenames_paragraph], hAlign='LEFT', vAlign='MIDDLE')
        vt_data.append(["Filenames", filenames_cell])
        vt_data.append(["Malicious Count", vt_result.get("Malicious_Count", "N/A")])
        vt_data.append(["Suspicious Count", vt_result.get("Suspicious_Count", "N/A")])
        vt_data.append(["Harmless Count", vt_result.get("Harmless_Count", "N/A")])
        vt_data.append(["Undetected Count", vt_result.get("Undetected_Count", "N/A")])
        vt_data.append(["VT_Reputation", vt_result.get("VT_Reputation(VirusTotal 내부 평판 점수)", "N/A")])
        vt_data.append(["Naive Score", vt_result.get("Naive Score(단순 계산 예시)", "N/A")])
        table_vt = Table(vt_data, colWidths=[2*inch, 4*inch])
        table_vt.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.darkred),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('VALIGN', (0,1), (-1,1), 'MIDDLE'),
        ]))
        story.append(table_vt)
        story.append(Spacer(1, 0.2*inch))

        # Engine table for Virustotal (Malicious Engines)
        if vt_result.get("Malicious_Engines"):
            engine_data = [["Engine", "Result"]]
            for eng in vt_result.get("Malicious_Engines", []):
                engine_data.append([eng.get("engine", "N/A"), eng.get("result", "N/A")])
            table_engines = Table(engine_data, colWidths=[3*inch, 3*inch])
            table_engines.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.darkblue),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
                ('FONTSIZE', (0,0), (-1,-1), 8),
            ]))
            story.append(Paragraph("Engines", styles['Heading3Indent']))
            story.append(table_engines)
            story.append(Spacer(1, 0.2*inch))

    llm = static.get("llm")
    if llm:
        if vt_result:
            story.append(Paragraph("(4) LLM Analysis Result", styles['Heading2Indent']))
        else:
            story.append(Paragraph("(3) LLM Analysis Result", styles['Heading2Indent']))
        llm_table_data = [["Field", "Value"]]
        probability = llm.get("probability", "N/A")
        result = llm.get("result", "N/A")
        llm_table_data.append(["probability", probability])
        llm_table_data.append(["LLM Result", result])
        table_llm = Table(llm_table_data, colWidths=[2*inch, 4*inch])
        table_llm.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.darkblue),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('FONTSIZE', (0,0), (-1,-1), 8),
        ]))
        story.append(table_llm)
        story.append(Spacer(1, 0.2*inch))

    # PageBreak 전에 Dynamic Analysis 섹션 시작 (새 페이지에서 시작)
    story.append(PageBreak())
    
    #################################
    # 2. Dynamic Analysis Section
    #################################
    story.append(Paragraph("2. Dynamic Analysis", styles['Heading1Indent']))
    dynamic = json_data.get("DynamicAnalysis", {})

    # (1) API Monitor
    process_frida = dynamic.get("process_frida", {})
    threads = process_frida.get("threads", {})
    if threads:
        story.append(Paragraph("(1) API Monitor", styles['Heading2Indent']))
    for tid, thread_info in threads.items():
        current_tid = tid
        if isinstance(thread_info, dict):
            classifications = thread_info.get("classification", {})
        else:
            continue
        
        if classifications:
            malware_type = classifications.get("malware_type", "")
            match_counts = classifications.get("match_counts", {})
            story.append(Paragraph(f"Thread ID: {current_tid} / Type : {malware_type}", styles['Heading3Indent']))
            cls_table_data = [["Type", "Count"]]
            for key, value in match_counts.items():
                cls_table_data.append([str(key), str(value)])
            
            table_cls = Table(cls_table_data, colWidths=[3*inch, 3*inch])
            table_cls.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.darkmagenta),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
                ('FONTSIZE', (0,0), (-1,-1), 8),
            ]))
            story.append(table_cls)
            story.append(Spacer(1, 0.2*inch))
    
    # (2) Event Monitor
    story.append(Paragraph("(2) Event Monitor", styles['Heading2Indent']))
    # event_security 처리
    event_security = dynamic.get("event_security")
    if event_security and isinstance(event_security, dict):
        story.append(Paragraph("Security Event", styles['Heading3Indent']))
        for ev_key, ev_data in event_security.items():
            if not ev_data:
                continue
            story.append(Paragraph(f"Event ID: {ev_key}", styles['Heading3Indent']))
            table_data = [["Field", "Value"]]
            for field in ["event_provider", "event_message", "count"]:
                value = ev_data.get(field, "N/A")
                if field == "event_message" and isinstance(value, str):
                    threshold = 60
                    if len(value) > threshold:
                        value = value[:threshold] + "..."
                table_data.append([field, str(value)])
            table_event = Table(table_data, colWidths=[2*inch, 4*inch])
            table_event.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.navy),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
                ('FONTSIZE', (0,0), (-1,-1), 8),
            ]))
            story.append(table_event)
            story.append(Spacer(1, 0.2*inch))
    
    # event_system 처리
    event_system = dynamic.get("event_system").get("system")
    if event_system and isinstance(event_system, dict):
        story.append(Paragraph("System Event", styles['Heading3Indent']))
        for ev_key, ev_data in event_system.items():
            if not ev_data:
                continue
            story.append(Paragraph(f"Event ID: {ev_key}", styles['Heading3Indent']))
            table_data = [["Field", "Value"]]
            for field in ["event_provider", "event_message", "count"]:
                value = ev_data.get(field, "N/A")
                if field == "event_message" and isinstance(value, str):
                    threshold = 60
                    if len(value) > threshold:
                        value = value[:threshold] + "..."
                table_data.append([field, str(value)])
            table_event = Table(table_data, colWidths=[2*inch, 4*inch])
            table_event.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.navy),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
                ('FONTSIZE', (0,0), (-1,-1), 8),
            ]))
            story.append(table_event)
            story.append(Spacer(1, 0.2*inch))
    
    # (3) Network Monitor
    network_traffic = dynamic.get("network_traffic").get("network")
    if network_traffic and isinstance(network_traffic, list):
        unique_ips = set()
        for entry in network_traffic:
            if isinstance(entry, dict):
                src = entry.get("src", "N/A").rsplit(".", 1)
                src = "[.]".join(src)
                sport = entry.get("sport", "N/A")
                dst = entry.get("dst", "N/A").rsplit(".", 1)
                dst = "[.]".join(dst)
                dport = entry.get("dport", "N/A")
                if src != "N/A" and sport != "N/A":
                    unique_ips.add(f"{src}:{sport}")
                if dst != "N/A" and dport != "N/A":
                    unique_ips.add(f"{dst}:{dport}")
            elif isinstance(entry, str):
                unique_ips.add(entry)
        net_data = [["IP Port List"]]
        for ip_port in sorted(unique_ips):
            net_data.append([ip_port])
        table_net = Table(net_data, colWidths=[6*inch])
        table_net.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.darkslategray),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('FONTSIZE', (0,0), (-1,-1), 8),
        ]))
        story.append(Paragraph("(3) Network Monitor", styles['Heading2Indent']))
        story.append(table_net)
        story.append(Spacer(1, 0.2*inch))
    
    # (4) Memory Monitor
    process_list = dynamic.get("memory").get("process_list")
    if process_list and isinstance(process_list, list):
        proc_data = [["Process List"]]
        for proc in process_list:
            proc_data.append([str(proc)])
        table_proc = Table(proc_data, colWidths=[6*inch])
        table_proc.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.darkslateblue),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('FONTSIZE', (0,0), (-1,-1), 8),
        ]))
        story.append(Paragraph("(4) Memory Monitor", styles['Heading2Indent']))
        story.append(Paragraph("Process List", styles['Heading3Indent']))
        story.append(table_proc)
        story.append(Spacer(1, 0.2*inch))
    strings = dynamic.get("memory").get("strings")
    if strings and isinstance(strings, list):
        str_data = [["Strings"]]
        for s in strings:
            str_data.append([str(s)])
        table_str = Table(str_data, colWidths=[6*inch])
        table_str.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.darkslateblue),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('FONTSIZE', (0,0), (-1,-1), 8),
        ]))
        story.append(Paragraph("Strings", styles['Heading3Indent']))
        story.append(table_str)
        story.append(Spacer(1, 0.2*inch))
    
    # (5) Registry Monitor
    story.append(Paragraph("(5) Registry Monitor", styles['Heading2Indent']))
    reg = dynamic.get("process_reg").get("reg_capture")
    if reg and isinstance(reg, dict):
        # Added 처리
        added = reg.get("added")
        if added:
            if isinstance(added, dict):
                added_data = [["Registry"]]
                for key, value in added.items():
                    added_data.append([Paragraph(key+"\\"+f"{value}", small_style)])
                col_widths = [6*inch]
            table_added = Table(added_data, colWidths=col_widths)
            table_added.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.darkolivegreen),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
                ('FONTSIZE', (0,0), (-1,-1), 8),
            ]))
            story.append(Paragraph("Added", styles['Heading3Indent']))
            story.append(table_added)
            story.append(Spacer(1, 0.2*inch))
    
        # Modified 처리
        modified = reg.get("modified")
        if modified:
            if isinstance(modified, list):
                mod_data = [["Registry"]]
                for item in modified:
                    mod_data.append([Paragraph(item, small_style)])
                col_widths = [6*inch]
            table_mod = Table(mod_data, colWidths=col_widths)
            table_mod.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.darkolivegreen),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
                ('FONTSIZE', (0,0), (-1,-1), 8),
            ]))
            story.append(Paragraph("Modified", styles['Heading3Indent']))
            story.append(table_mod)
            story.append(Spacer(1, 0.2*inch))
    
        # Deleted 처리
        deleted = reg.get("deleted")
        if deleted:
            if isinstance(deleted, dict):
                del_data = [["Registry"]]
                for key, value in deleted.items():
                    del_data.append([Paragraph(key+"\\"+f"{value}", small_style)])
                col_widths = [6*inch]
            table_del = Table(del_data, colWidths=col_widths)
            table_del.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.darkolivegreen),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
                ('FONTSIZE', (0,0), (-1,-1), 8),
            ]))
            story.append(Paragraph("Deleted", styles['Heading3Indent']))
            story.append(table_del)
            story.append(Spacer(1, 0.2*inch))
    
    # (6) Final Type
    story.append(Paragraph("(6) Final Type", styles['Heading2Indent']))
    final_type = dynamic.get("final_type", "N/A")
    final_table_data = [["Field", "Value"],
                        ["Type", str(final_type)]]
    table_final = Table(final_table_data, colWidths=[2*inch, 4*inch])
    table_final.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.darkred),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('GRID', (0,0), (-1,-1), 1, colors.black),
        ('FONTSIZE', (0,0), (-1,-1), 8),
    ]))
    story.append(table_final)
    story.append(Spacer(1, 0.2*inch))
    
    # 새 페이지에서 Appendix 시작
    story.append(PageBreak())
    story.append(Paragraph("Appendix", styles['Heading1Indent']))
    imported_libraries = pe_analysis.get("imported_libraries", {})
    if imported_libraries:
        for lib, details in imported_libraries.items():
            story.append(Paragraph(f"Library: {lib}", styles['Heading2Indent']))
            suspicious = get_suspicious_list(details)
            functions = details.get("functions", [])
            n_rows = max(len(suspicious), len(functions))
            if n_rows == 0:
                n_rows = 1
            table_rows = [["Suspicious Functions", "Entire Functions"]]
            for i in range(n_rows):
                susp_item = suspicious[i] if i < len(suspicious) else ""
                func_item = functions[i] if i < len(functions) else ""
                susp_par = Paragraph(susp_item, small_style)
                func_par = Paragraph(func_item, small_style)
                table_rows.append([susp_par, func_par])
            table_lib = Table(table_rows, colWidths=[3*inch, 3*inch])
            table_lib.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.darkorange),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
                ('FONTSIZE', (0,0), (-1,-1), 8),
            ]))
            story.append(table_lib)
            story.append(Spacer(1, 0.2*inch))
    
    story.append(PageBreak())

    process_frida = dynamic.get("process_frida", {})
    threads = process_frida.get("threads", {})
    story.append(Paragraph("API/Function Calls", styles['Heading2Indent']))

    for tid, thread_info in threads.items():
        current_tid = tid
        if isinstance(thread_info, dict):
            api_calls = thread_info.get("function or api", [])
        elif isinstance(thread_info, list):
            api_calls = thread_info
        else:
            continue
        if api_calls:
            # Thread ID 및 API/Function Calls 테이블 생성 (api_calls가 빈 리스트여도 header만 있는 테이블 생성)
            story.append(Paragraph(f"Thread ID: {current_tid}", styles['Heading3Indent']))
            # 테이블 데이터: header만 포함한 후, 빈 리스트이면 추가 행이 없음.
            api_table_data = [["API/Function"]] + [[call] for call in api_calls if "frida" not in call]
            table_api = Table(api_table_data, colWidths=[6*inch])
            table_api.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.darkgreen),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
                ('FONTSIZE', (0,0), (-1,-1), 8),
            ]))
            
            story.append(Spacer(1, 0.05*inch))
            story.append(table_api)
            story.append(Spacer(1, 0.1*inch))

    story.append(PageBreak())

    network_traffic = dynamic.get("network_traffic").get("network")
    if network_traffic and isinstance(network_traffic, list):
        net_data = [["Protocol", "Src:Port", "Dst:Port", "Payload Len"]]
        for entry in network_traffic:
            if isinstance(entry, dict):
                protocol = entry.get("protocol", "N/A")
                src = entry.get("src", "N/A").rsplit(".", 1)
                src = "[.]".join(src)
                sport = entry.get("sport", "N/A")
                dst = entry.get("dst", "N/A").rsplit(".", 1)
                dst = "[.]".join(dst)
                dport = entry.get("dport", "N/A")
                payload = entry.get("payload_len", "N/A")
                net_data.append([protocol, f"{src}:{sport}", f"{dst}:{dport}", str(payload)])
            elif isinstance(entry, str):
                net_data.append([entry, "N/A", "N/A", "N/A"])
        table_net = Table(net_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch])
        table_net.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.darkslategray),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('FONTSIZE', (0,0), (-1,-1), 8),
        ]))
        story.append(Paragraph("Network Traffic", styles['Heading2Indent']))
        story.append(table_net)
        story.append(Spacer(1, 0.2*inch))

    story.append(PageBreak())
    doc.build(story)

if __name__ == "__main__":
    res = get_json_from_elk()
    if res and res.get('hits', {}).get('hits'):
        json_data = res['hits']['hits'][0]['_source']
        if isinstance(json_data, str):
            json_data = json.loads(json_data)
        create_pdf_report(json_data, "styled_report.pdf")
        logging.info("PDF build successful")
    else:
        logging.error("Elasticsearch에서 문서를 찾을 수 없습니다.")
