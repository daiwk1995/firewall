import sys
import csv
import collections
class Firewall():
    def __init__(self,path):
        self.InboundTCP = collections.defaultdict(set)
        self.OutboundTCP = collections.defaultdict(set)
        self.InboundUDP = collections.defaultdict(set)
        self.OutboundUDP = collections.defaultdict(set)
        with open(path) as f:
            reader = csv.reader(f,delimiter = ',')
            for row in reader:
                self.pre_process(row)
    def pre_process(self,row):
        direction, protocol, port, ip = row[0],row[1],row[2],row[3]
        if direction == "inbound":
            if protocol == "tcp":
                self.process(self.InboundTCP,port,ip)
            elif protocol == "udp":
                self.process(self.InboundUDP,port,ip)
        elif direction == "outbound":
            if protocol == "tcp":
                self.process(self.OutboundTCP,port,ip)
            elif protocol == "udp":
                self.process(self.OutboundUDP,port,ip)
    def process(self,dic,port,ip):
        if('-' in port):
            gap = port.split('-')
            low = int(gap[0])
            high = int(gap[1])
            for i in range(low, high + 1):
                dic[i].add(ip)
        else:
            dic[int(port)].add(ip)

    def accept(self,direction,protocol,port,ip_address):
        if direction == "inbound":
            if protocol == "tcp":
                if port in self.InboundTCP:
                    if ip_address in self.InboundTCP[port]:
                        return True
                    else:
                        return False
                else:
                    return False
            elif protocol == "udp":
                if port in self.InboundUDP:
                    if ip_address in self.InboundUDP[port]:
                        return True
                    else:
                        return False
                else:
                    return False
        elif direction == "outbound":
            if protocol == "tcp":
                if port in self.OutboundTCP:
                    if ip_address in self.OutboundTCP[port]:
                        return True
                    else:
                        return False
                else:
                    return False
            elif protocol == "udp":
                if port in self.OutboundUDP:
                    if ip_address in self.OutboundUDP[port]:
                        return True
                    else:
                        return False
                else:
                    return False
if __name__ == "__main__":
    fw=Firewall("rules.csv")
    input = sys.argv[1]
    f = open(input,"r")
    for line in f:
        x = [a.strip() for a in line.split(',')]
        x = [a.strip('\"') for a in x]
        print(fw.accept(x[0],x[1],int(x[2]),x[3]))
