import psutil
import json

def socket_connection_established_info():
    net = {}
    for connection in psutil.net_connections():
        if connection.status=="ESTABLISHED":
            net.setdefault(connection.pid,{"laddr":connection.laddr.ip,"lport":connection.laddr.port,"raddr":connection.raddr.ip,"rport":connection.raddr.port})
    
    procs =psutil.process_iter(['pid','name','username'])

    for p in procs:
        if p.pid in net.keys():
            net[p.pid].update({"service":p.name()})

    print(json.dumps(net,indent=4))

def main():
    socket_connection_established_info()

if __name__=="__main__":
    main()