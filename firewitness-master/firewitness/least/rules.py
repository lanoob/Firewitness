import iptc
import itertools

def get_all_rules_for_chain():
    table = iptc.Table(iptc.Table.FILTER)
    rules = []
    for chain in table.chains:
        print("Chain ", chain.name)
        for rule in chain.rules:
            print(rule)
            for match in rule.matches:
                pass
            rules.append(rule)
    return rules



# finds the endpoint packets if the firewall and property agree also used for friend rules
#
# property - single rule ( (src ip range), (dst ip range), (action *1 or 0) )
# firewall - list of rules ( (src ip range), (dst ip range), (action *1 or 0) )
# return - list of "agree packets"
def get_agree_packets(property,firewall):
    list = []   #list of witness packets
    packet = [] #a single witness packet
    for i in firewall:
        if property[2] == i[2]:
            r = i[0][1] + 1
            c = i[1][1] + 1
            packet.append(r)
            packet.append(c)
            list.append(packet)
            del packet[:]
    return list

# finds the endpoint packets if the firewall and property disagree also used for enemy rules
#
# property - single rule ( (src ip range), (dst ip range), (action *1 or 0) )
# firewall - list of rules ( (src ip range), (dst ip range), (action *1 or 0) )
# return - list of "disagree packets"
def get_disagree_packets(property,firewall):
    list = []
    packet = []
    for i in firewall:
        if property[2] != i[2]:
            r = i[0][0]
            c = i[1][0]
            packet.append(r)
            packet.append(c)
            list.append(packet)
            del packet[:]
    return list
#gets the endpoint packets of the list that agrees with the property and of the list that
#disagrees with the property
#
#agree_list - list of packets from the firewall that agree with the property
#disagree_list - list of packets from firewall that disagree with the property
def get_endpoints(agree_list, disagree_list):
    endpoint_list = []
    endpoint_packet = []
    r1 = 0
    r2 = 0
    temp = 0

    ####################################################
    #gets the endpoints of the agree list (higher bounds)
    for i in agree_list:
        if r1 >= r2:
            temp = r1
            r2 = temp
            r1 = agree_list[i][0]
        elif r1 < agree_list[i][0]:
            r2 = r1
            r1 = agree_list[i][0]
    endpoint_packet.append(r1)
    endpoint_packet.append(r2)
    endpoint_list.append(endpoint_packet)
    del endpoint_packet[:]

    for j in agree_list:
        if r1 >= r2:
            temp = r1
            r2 = temp
            r1 = agree_list[j][1]
        elif r1 < agree_list[j][1]:
            r2 = r1
            r1 = agree_list[j][1]
    endpoint_packet.append(r1)
    endpoint_packet.append(r2)
    endpoint_list.append(endpoint_packet)

    ######################################################
    #gets the endpoints of the disagree list (lower bounds)
    for i in disagree_list:
        if r1 >= r2:
            temp = r1
            r2 = temp
            r1 = disagree_list[i][0]
        elif r1 > disagree_list[i][0]:
            r2 = r1
            r1 = disagree_list[i][0]
    endpoint_packet.append(r1)
    endpoint_packet.append(r2)
    endpoint_list.append(endpoint_packet)
    del endpoint_packet[:]

    for j in agree_list:
        if r1 >= r2:
            temp = r1
            r2 = temp
            r1 = disagree_list[j][1]
        elif r1 > disagree_list[j][1]:
            r2 = r1
            r1 = disagree_list[j][1]
    endpoint_packet.append(r1)
    endpoint_packet.append(r2)
    endpoint_list.append(endpoint_packet)

    return endpoint_list

#gets the endpoint packets and takes the cartesean product in order to yield test packets
#
#endpoint_list - a list of endpoints from the firewall rules
#return - a list of test packets to use on the firewall
def get_test_packets(endpoint_list):
    test_packets = []
    temp_list = []
    while len(endpoint_list) != 0:
        temp_list.append(endpoint_list[0])
        temp_list.append(endpoint_list[1])
        del endpoint_list[:2]
        for element in itertools.product(temp_list):
            test_packets.append(element)
        del temp_list[:]
    return endpoint_list

#takes a list of touples and finds the least witness packet.
def get_least_witness_packet(list):
    return