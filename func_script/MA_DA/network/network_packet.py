from scapy.all import *

#데이터 유출 및 수집
def capture_data(interface):
    """
    
    Ether / IP / UDP / DNS Qry b'clientservices.googleapis.com.'
    Ether / IP / UDP / DNS Qry b'clientservices.googleapis.com.'
    Ether / IP / UDP / DNS Ans 142.250.196.99
    Ether / IP / UDP / DNS Ans
    Ether / IP / TCP 10.0.2.15:49877 > 142.250.196.99:https S
    Ether / IP / UDP / DNS Qry b'accounts.google.com.'
    Ether / IP / UDP / DNS Qry b'accounts.google.com.'
    Ether / IP / UDP / DNS Qry b'www.google.com.'
    Ether / IP / UDP / DNS Qry b'www.google.com.'
    Ether / IP / UDP / DNS Ans 74.125.23.84
    
    """
    packets = sniff(iface=interface,count=10)
    for packet in packets:
        print(packet)
        if Raw in packet:
            print(packet[Raw].load)

#capture_data("Ethernet")

#DNS 트래픽 분석
def dns_analyze(packet):

    """
    
    DNS Qry b'clientservices.googleapis.com.'
    DNS Qry b'clientservices.googleapis.com.'
    DNS Ans 216.58.220.99
    DNS Ans
    DNS Qry b'accounts.google.com.'
    DNS Qry b'accounts.google.com.'
    DNS Qry b'www.google.com.'
    DNS Qry b'www.google.com.'
    DNS Ans 74.125.203.84
    DNS Ans
    DNS Ans 142.250.196.132
    DNS Ans
    DNS Qry b'ogads-pa.googleapis.com.'
    DNS Qry b'ogads-pa.googleapis.com.'
    DNS Ans 142.251.42.170
    DNS Ans
    DNS Qry b'play.google.com.'
    DNS Qry b'play.google.com.'
    DNS Qry b'jvvp.tistory.com.'
    DNS Qry b'jvvp.tistory.com.'
    DNS Ans b'wildcard-tistory-fz0x1pwf.kgslb.com.'
    DNS Qry b'google-ohttp-relay-safebrowsing.fastly-edge.com.'
    DNS Qry b'google-ohttp-relay-safebrowsing.fastly-edge.com.'
    DNS Ans 146.75.49.91
    DNS Ans
    DNS Qry b'play.google.com.'
    DNS Qry b'play.google.com.'
    DNS Qry b'jvvp.tistory.com.'
    DNS Qry b'play.google.com.'
    DNS Qry b'play.google.com.'
    DNS Qry b'jvvp.tistory.com.'
    DNS Ans 172.217.25.174
    DNS Ans
    DNS Ans b'wildcard-tistory-fz0x1pwf.kgslb.com.'
    DNS Qry b'search1.daumcdn.net.'
    DNS Qry b'search1.daumcdn.net.'
    DNS Qry b't1.daumcdn.net.'
    DNS Qry b't1.daumcdn.net.'
    DNS Ans b'search-xi6mgp35.kgslb.com.'
    DNS Ans b'search-xi6mgp35.kgslb.com.'
    DNS Ans b't1-wg2vgaja.kgslb.com.'
    DNS Ans b't1-wg2vgaja.kgslb.com.'
    DNS Qry b'googleads.g.doubleclick.net.'
    DNS Qry b'googleads.g.doubleclick.net.'
    DNS Ans 172.217.174.98
    DNS Ans
    DNS Qry b'pagead2.googlesyndication.com.'
    DNS Qry b'pagead2.googlesyndication.com.'
    DNS Ans 172.217.26.226
    DNS Ans
    DNS Qry b'webid.ad.daum.net.'
    DNS Qry b'webid.ad.daum.net.'
    DNS Ans b'webid-73kbtbvm.kgslb.com.'
    DNS Ans b'webid-73kbtbvm.kgslb.com.'
    DNS Qry b'www.googletagmanager.com.'
    DNS Qry b'www.googletagmanager.com.'
    DNS Qry b'www.google-analytics.com.'
    DNS Qry b'www.google-analytics.com.'
    DNS Ans 142.251.222.40
    DNS Ans
    DNS Ans b'www-alv.google-analytics.com.'
    DNS Ans 142.250.207.14
    DNS Qry b'content-autofill.googleapis.com.'
    DNS Qry b'content-autofill.googleapis.com.'
    DNS Qry b'webid.kakao.com.'
    DNS Qry b'webid.kakao.com.'
    DNS Ans 172.217.174.106
    DNS Ans
    DNS Ans b'webid-73kbtbvm.kgslb.com.'
    DNS Ans b'webid-73kbtbvm.kgslb.com.'
    DNS Qry b'googleads.g.doubleclick.net.'
    DNS Qry b'googleads.g.doubleclick.net.'
    DNS Ans 172.217.174.98
    DNS Ans
    DNS Qry b'display.ad.daum.net.'
    DNS Qry b'display.ad.daum.net.'
    DNS Ans b'display-ad-rgt0me85.kgslb.com.'
    DNS Ans b'display-ad-rgt0me85.kgslb.com.'    
    
    """

    if packet.haslayer(DNS):
        print(packet[DNS].summary())

#sniff(prn=dns_analyze, filter="udp port 53", store=0)

#비정상적인 프로토콜 및 포트 사용 <- 이상함
def analyze_protocol_port(packet):
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        sport = packet.sport
        dport = packet.dport
        if dport not in [80, 443, 53]: #Well Known Port인 포트들을 배열이 추가
            print(packet.summary)

#sniff(prn=analyze_protocol_port, store = 0)

#패킷 페이로드 분석
def payload_analyze(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        #페이로드 분석 로직 추가
        print(payload)

#sniff(prn=payload_analyze, store = 0)

#연결대상 분석
def analyze_connection(packet):

    """
    
    Source : 10.0.2.15 -> Destination : 20.189.173.7
    Source : 10.0.2.15 -> Destination : 20.189.173.7
    Source : 10.0.2.15 -> Destination : 20.189.173.7
    Source : 20.189.173.7 -> Destination : 10.0.2.15
    
    """

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Source : {src_ip} -> Destination : {dst_ip}")

#sniff(prn=analyze_connection, store = 0)

#트래픽 패턴 및 행동 분석
def analyze_traffic_patterns(packet):

    """
    
    Ether / IP / TCP 10.0.2.15:49984 > 51.105.71.136:https FA
    Ether / IP / TCP 51.105.71.136:https > 10.0.2.15:49984 A / Padding
    Ether / IP / TCP 51.105.71.136:https > 10.0.2.15:49984 FA / Padding
    Ether / IP / TCP 10.0.2.15:49984 > 51.105.71.136:https A
    Ether / IP / TCP 10.0.2.15:49985 > 118.214.79.16:http FA
    Ether / IP / TCP 118.214.79.16:http > 10.0.2.15:49985 A / Padding
    Ether / IP / TCP 118.214.79.16:http > 10.0.2.15:49985 FA / Padding
    Ether / IP / TCP 10.0.2.15:49985 > 118.214.79.16:http A
    Ether / IP / UDP / mDNS Ans b'WinDev2407Eval._dosvc._tcp.local.'
    Ether / IP / UDP / mDNS Qry b'WinDev2407Eval._dosvc._tcp.local.'    
    
    """

    if packet.haslayer(IP):
        #트래픽 패턴 및 행동 분석 로직 추가가
        print(packet.summary())

#sniff(prn = analyze_traffic_patterns, store = 0)

#암호화 및 인코딩 기법 분석
def analyze_encryption(packet):
    if packet.haslayer(Raw):
        #암호화 및 인코딩 분석 로직 추가가
        payload = packet[Raw].load
        print(payload)

#sniff(prn = analyze_encryption, store = 0)

#상호작용하는 내부 호스트 식별
def identify_internal_hosts(packet):

    """
    
    Internal Host : 142.250.198.14 -> 10.0.2.15
    Internal Host : 10.0.2.15 -> 142.250.196.106
    Internal Host : 142.250.196.106 -> 10.0.2.15
    Internal Host : 142.250.196.106 -> 10.0.2.15
    Internal Host : 10.0.2.15 -> 142.250.196.106
    Internal Host : 10.0.2.15 -> 224.0.0.251
    Internal Host : 10.0.2.15 -> 224.0.0.251
    Internal Host : 10.0.2.15 -> 224.0.0.251
    
    """

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        #내부 호스트 식별 로직 추가
        print(f"Internal Host : {src_ip} -> {dst_ip}")

#sniff(prn = identify_internal_hosts, store = 0)

#로그 및 메타데이터 분석
def analuze_logs(packet):
    if packet.haslayer(IP):
        #로그 및 메타데이터 분석 로직 추가
        print(packet.summary())

#sniff(prn=analuze_logs, store = 0)