import sys
import csv
import collections
class Firewall():
    def __init__(self,path):
        self.InboundTCP = {}
        self.OutboundTCP = {}
        self.InboundUDP = {}
        self.OutboundUDP = {}
        #read the rule file and create the rules and record it in dictionary
        with open(path) as f:
            reader = csv.reader(f,delimiter = ',')
            for row in reader:
                self.pre_process(row)
    #seperate the input rules depend on the direction type and protocol type. record them in different dictionary.
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
        # the case if the port is a range,seperate record
        if '-' in port:
            gap = port.split('-')
            low = int(gap[0])
            high = int(gap[1])
            for i in range(low, high + 1):
                dic[i] = [ip]
        # the case if the ip is a range. seperate four part by '.'
        elif '-' in ip:
            gap = ip.split('-')
            tmp1 = gap[0].split('.')
            tmp2 = gap[1].split('.')
            dic[int(port)] = [(tmp1[0],tmp2[0]),(tmp1[1],tmp2[1]),(tmp1[2],tmp2[2]),(tmp1[3],tmp2[3])]
        else:
            dic[int(port)] = [ip]
    # test if the input is valid. the corner case if the ip is a range.
    def accept(self,direction,protocol,port,ip_address):
        if direction == "inbound":
            if protocol == "tcp":
                if port in self.InboundTCP:
                    if len(self.InboundTCP[port]) > 1:
                        tmp = ip_address.split('.')
                        if self.InboundTCP[port][0][0] <= tmp[0] <= self.InboundTCP[port][0][1] and self.InboundTCP[port][1][0] <= tmp[1] <= self.InboundTCP[port][1][1] and self.InboundTCP[port][2][0] <= tmp[2] <= self.InboundTCP[port][2][1] and self.InboundTCP[port][3][0] <= tmp[3] <= self.InboundTCP[port][3][1]:
                            return True
                        else:
                            return False
                    else:
                        return self.InboundTCP[port][0] == ip_address
                else:
                    return False
            elif protocol == "udp":
                if port in self.InboundUDP:
                    if len(self.InboundUDP[port]) > 1:
                        tmp = ip_address.split('.')
                        if self.InboundUDP[port][0][0] <= tmp[0] <= self.InboundUDP[port][0][1] and self.InboundUDP[port][1][0] <= tmp[1] <= self.InboundUDP[port][1][1] and self.InboundUDP[port][2][0] <= tmp[2] <= self.InboundUDP[port][2][1] and self.InboundUDP[port][3][0] <= tmp[3] <= self.InboundUDP[port][3][1]:
                            return True
                        else:
                            return False
                    else:
                        return self.InboundUDP[port][0] == ip_address
                else:
                    return False
        elif direction == "outbound":
            if protocol == "tcp":
                if port in self.OutboundTCP:
                    if len(self.OutboundTCP[port]) > 1:
                        tmp = ip_address.split('.')
                        if self.OutboundTCP[port][0][0] <= tmp[0] <= self.OutboundTCP[port][0][1] and self.OutboundTCP[port][1][0] <= tmp[1] <= self.OutboundTCP[port][1][1] and self.OutboundTCP[port][2][0] <= tmp[2] <= self.OutboundTCP[port][2][1] and self.OutboundTCP[port][3][0] <= tmp[3] <= self.OutboundTCP[port][3][1]:
                            return True
                        else:
                            return False
                    else:
                        return self.OutboundTCP[port][0] == ip_address
                else:
                    return False
            elif protocol == "udp":
                if port in self.OutboundUDP:
                    if len(self.OutboundUDP[port]) > 1:
                        tmp = ip_address.split('.')
                        if self.OutboundUDP[port][0][0] <= tmp[0] <= self.OutboundUDP[port][0][1] and self.OutboundUDP[port][1][0] <= tmp[1] <= self.OutboundUDP[port][1][1] and self.OutboundUDP[port][2][0] <= tmp[2] <= self.OutboundUDP[port][2][1] and self.OutboundUDP[port][3][0] <= tmp[3] <= self.OutboundUDP[port][3][1]:
                            return True
                        else:
                            return False
                    else:
                        return self.OutboundUDP[port][0] == ip_address
                else:
                    return False
if __name__ == "__main__":
    #read the csv file to construct the firewall
    fw=Firewall("rules.csv")
    #read the test case
    input = sys.argv[1]
    f = open(input,"r")
    for line in f:
        #preprocess the input avoid whitespace between the data.
        x = [a.strip() for a in line.split(',')]
        x = [a.strip('\"') for a in x]
        print(fw.accept(x[0],x[1],int(x[2]),x[3]))
