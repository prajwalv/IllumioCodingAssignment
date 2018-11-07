class firewall():
    # contructor to initialise the path.
    def __init__(self,path):
        self.path = path

    # code to check if the csv path exist
    def check_file_path(self):
        import os
        try:
            exist = os.path.isfile(self.path)
            if exist:
                return True
            else:
                return False
        except FileNotFoundError:
            print("File doesn't exist\n")
            exit()

    # function to read the data from csv
    def read_csv(self):
        import csv
        csv_rules = []
        status = self.check_file_path()
        if status:
            with open(self.path,encoding="utf8") as csvfile:
                readCSV = csv.reader(csvfile, delimiter=',')
                for row in readCSV:
                    direction,protocol,port_range,ip_range = validate_rule(row[0],row[1],row[2],row[3])
                    all_rules = get_all_rules_in_csv(row,direction,protocol,port_range,ip_range)
                    for rule in all_rules:
                        frule = rule.replace("space","")
                        csv_rules.append(frule)
            return csv_rules
        else:
            print("File not found!")
            exit()

    # The function which performs required validation.
    # First it checks the validity of all the four parameters
    # If all the four parameters are valid, it will convert the given parameters to a string(without spaces, as all the firewall rules are stored in this format)
    # Searchs the given rule in the list of available rules in the list.
    # Returns True if it matches, else returns False

    def accept_packet(self,direction,protocol,port,ip):
        csv_rule_list = self.read_csv()
        dstatus = check_direction(direction)
        pstatus = check_protocol(protocol)
        postatus = check_port(port)
        istatus = check_particular_ip(ip)

        if dstatus == True and pstatus == True and postatus[0] == True and istatus == True:
            rule = direction+protocol+str(port)+ip
            if rule in csv_rule_list:
                return True
            else:
                return False
        else:
            return False

# checks if a given direction in the csv file and input parameter is valid.
def check_direction(direction):
    direction_lower = direction.lower()
    if direction_lower == "inbound" or direction_lower == "outbound":
        return True
    else:
        return False

# checks if a given protocol in the csv file and input parameter is valid.
def check_protocol(protocol):
    if protocol == 'tcp' or protocol == 'udp':
        return True
    else:
        return False

# checks if a given port in the csv file and input parameter is valid.
# if the port is a given range returns the start and end of the range
def check_port(pt):
    port = str(pt)
    if port == '-1':
        return False
    elif ~(port.find('-')):
        start = port[:port.find('-')]
        end = port[port.find('-')+1:]
        if start ==  end:
            return False, int(0), int(0)
        elif int(start) >= 1 and int(start) <= 65535 and int(end) >= 1 and int(end) <= 65535:
            return True,int(start),int(end)
        else:
            return False,int(0),int(0)
    else:
        pt = int(pt)
        if pt >= 1 and pt <= 65535:
            return True,int(1),int(1)
        else:
            return False,int(0),int(0)

# checks if a given IP Address in the csv file and input parameter is valid.
def check_particular_ip(ip):
    new_ip = ip.split(".")
    for octet in new_ip:
        if int(octet) >= 0 or int(octet) <=  255:
            return True
        else:
            print("Invalid Ip")
            return False

# function to retrieve the IP address range between a given range.
def get_ip_range(start_ip, end_ip):
    start = list(map(int, start_ip.split(".")))
    end = list(map(int, end_ip.split(".")))
    temp = start
    ip_range = []
    ip_range.append(start_ip)
    while temp != end:
        start[3] += 1
        for i in reversed(range(1,4)):
            if temp[i] == 256:
                temp[i] = 0
                temp[i - 1] += 1
        ip_range.append(".".join(map(str, temp)))
    return ip_range

# function to get the start and end range of IP Addresses
# returns a list of IP Address bewteen the given range
def check_IP(ip):
    if ~(ip.find('-')):
        start_ip = ip[:ip.find('-')]
        end_ip = ip[ip.find('-') + 1:]
        ip_range = get_ip_range(start_ip,end_ip)
        return ip_range
    else:
        return ip

# checks all the values in the csv file are valid
def validate_rule(direction, protocol, port, ip):
    direction_status = check_direction(direction)
    if direction_status:
        direction = direction
    else:
        print("Invalid Direction")

    protocol_status = check_protocol(protocol)
    if protocol_status:
        protocol = protocol
    else:
        print("Invalid protocol")

    port_status,start,end = check_port(port)
    port_range = []
    if port_status and start >= 1 and end >= 2 :
        for i in range(start,end+1):
            port_range.append(i)
    elif port_status and start == 1 and end == 1:
            port_range.append(port)
    else:
        print("Invalid port")

    ip_range = check_IP(ip)

    return direction,protocol,port_range,ip_range

# function to generate all the firewall rules from the csv file
def get_all_rules_in_csv(row,direction,protocol,port_range,ip_range):
    port_rules = []
    for port in range(len(port_range)):
        if type(ip_range) == list:
            for irule in ip_range:
                rule = direction + 'space' + protocol + 'space' + str(port_range[port]) + "space" + str(irule) #have used value 'space' as a filler which will be later removed
                port_rules.append(rule)

        else:
            rule = direction +'space'+ protocol + 'space'+str(port_range[port]) + "space" + str(ip_range)
            port_rules.append(rule)
    return port_rules


fw = firewall("path/to/firewallRules.csv")
# print(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"))
# print(fw.accept_packet("inbound", "udp", 53, "192.168.2.4"))
# print(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
# print(fw.accept_packet("inbound", "udp", 10234, "192.168.10.11"))
