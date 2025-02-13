#!/usr/bin/python3

import pox.openflow.libopenflow_01 as of

# KAIST CS341 SDN Lab Task 2, 3, 4
#
# All functions in this file runs on the controller:
def init(self,net):
    self.net = net
#       - runs only once for network, when initialized
#       - the controller should process the given network structure for future behavior
#def addrule(self,switchname, connection):

 #   match_arp = of.ofp_match()
  #  match_arp.dl_type = 0x0806

   # match_ipv4 = of.ofp_match()
#    match_ipv4.dl_type = 0x0800
 #   flood_action = [of.ofp_action_output(port = of.OFPP_FLOOD)]
  #  flow_mod_arp = of.ofp_flow_mod()
   # flow_mod_arp.match = match_arp
   # flow_mod_arp.actions = flood_action
        
 #   flow_mod_ipv4 = of.ofp_flow_mod()
 #   flow_mod_ipv4.match = match_ipv4
#    flow_mod_ipv4.actions = flood_action
#    connection.send(flow_mod_arp)
#    connection.send(flow_mod_ipv4)
#       - runs when a switch connects to the controller
#       - the controller should insert routing rules to the switch
#def  handlePacket(self,packet, connection):
#    return
#       - runs when a switch sends unhandled packet to the controller
#       - the controller should decide whether to handle the packet:
#           - let the switch route the packet
#           - drop the packet
#
# Task 2: Getting familiarized with POX 
# Let switches "flood" packets

# 
# Task 3: Implementing a Simple Routing Protocol
#   - Let switches route via Dijkstra
#   - Match ARP and ICMP over IPv4 packets
#
# Task 4: Redirecting all DNS request packets to controller 
#   - Let switches send all DNS packets to Controller
#       - Create proper forwarding rules, send all DNS queries and responses to the controller
#       - HTTP traffic should not be forwarded to the controller
#       
# Task 5: Implementing a Simple DNS-based Censorship
#   - Check DNS request
#       - If request contains task5-block.com, return empty DNS response instead of routing it
#       
# Task 6: Implementing more efficient DNS-based censorship 
#   - Let switches send only DNS query packets to Controller
#       - Create proper forwarding rules, send only DNS queries to the controller
#   - Check if DNS query contains cs341dangerous.com
#       - If such query is found, insert a new rule to switch to track the DNS response
#           - let the swtich route DNS response to the controller
#       - When the corresponding DNS response arrived, do followings:
#           - parse DNS response, insert a new rule to block all traffic from/to the server
#           - reply the DNS request with empty DNS response
#       - For all other packets, route them normally
#
# Task 7: Extending Censorship to Normal Network
#   - At any time, HTTP and DNS server can be changed by following:
#     - Create new server, hosting either task7-block-<one or more digits>.com or task7-open-<one or more digits>.com
#       - DNS server adds new record, HTTP server adds new domain
#     - For certain domain, hosting server changes
#       - DNS server changes record, HTTP server is replaced to another one
#     - For certain domain, hosting stops
#       - DNS server removes record, HTTP server removes the domain
#  - For 3 changes above, HTTP servers and DNS servers are changed instantly
#  - Assume that
#    - single IP might host multiple domains
#    - the IP should be blocked if it hosts at least one task7-block-<one or more digits>.com
#    - Only one IP is assigned to one domain
#    - If you detect different DNS response for same DNS request, assume that previous IP does not host the domain anymore


###
# If you want, you can define global variables, import Python built-in libraries, or do others
###
import heapq
def init(self, net) -> None:
    #
    # net argument has following structure:
    # 
    # net = {
    #    'hosts': {
    #         'h1': {
    #             'name': 'h1',
    #             'IP': '10.0.0.1',
    #             'links': [
    #                 # (node1, port1, node2, port2, link cost)
    #                 ('h1', 1, 's1', 2, 3)
    #             ],
    #         },
    #         ...
    #     },
    #     'switches': {
    #         's1': {
    #             'name': 's1',
    #             'links': [
    #                 # (node1, port1, node2, port2, link cost)
    #                 ('s1', 2, 'h1', 1, 3)
    #             ]
    #         },
    #         ...
    #     }
    # }
    #

    self.net = net
    self.ip_map = {}
    switches = list(net['switches'].keys())
    hosts = list(net['hosts'].keys())

    for switch in switches:
        switch_ = net['switches'].get(switch)
        if switch_ and "IP" in switch_:
            self.ip_map[switch] = switch_["IP"]

    for host in hosts:
        host_ = net['hosts'].get(host)  
        if host_ and "IP" in host_:
            self.ip_map[host] = host_["IP"]


    matrix_size = len(switches) + len(hosts)

    matrix = [[0] * matrix_size for i in range(matrix_size)]
    for host in hosts:
        links = net["hosts"][host]["links"]
        for link in links:
            from_ = link[0]
            to_ = link[2]
            cost = int(link[4])

            from_ = int(from_[1:]) + len(switches) - 1
            if to_[0] == "h":
                to_ = int(to_[1:]) + len(switches) - 1
            else:
                to_ = int(to_[1:]) - 1

            matrix[from_][to_] = cost
            matrix[to_][from_] = cost

    # do same for switches
        for switch in switches:
            links = net["switches"][switch]["links"]
            for link in links:


                from_ = link[0]
                to_ = link[2]
                cost = int(link[4])
                from_ = int(from_[1:]) - 1

                if to_[0] == "s":
                    to_ = int(to_[1:]) - 1
                else:
                    to_ = int(to_[1:]) + len(switches) - 1

                matrix[from_][to_] = cost
                matrix[to_][from_] = cost
    
    self.routing_table = {}
    for i in range(matrix_size):

        if i < len(switches):
            start_name = "s" + str(i +1)

        else:
            start_name = "h" + str(i - len(switches) + 1)


        shortest_paths = dijkstra(matrix, i, matrix_size)
        self.routing_table[start_name] = {}

        for dest_index, path in shortest_paths.items():
            if dest_index != i:
                next_hop_index = path[1]  
                
                if dest_index < len(switches):
                    dest_name = "s" + str(dest_index +1)

                else:
                    dest_name = "h" + str(dest_index - len(switches) + 1)

                if next_hop_index < len(switches):
                    next_name = "s" + str(next_hop_index +1)

                else:
                    next_name = "h" + str(next_hop_index - len(switches) + 1)

                if start_name.startswith('s'):
                    links = net['switches'][start_name]['links']
                else:
                    links = net['hosts'][start_name]['links']

            
            
                for link in links:
                    if link[2] == next_name:
                        out_port = link[1]
                        break

                self.routing_table[start_name][dest_name] = out_port

def dijkstra(adjacency_matrix, start, total_nodes):

    distances = {node: float('inf') for node in range(total_nodes)}
    distances[start] = 0
    priority_queue = [(0, start)]
    paths = {start: [start]}

    while priority_queue:
        current_distance, current_node = heapq.heappop(priority_queue)

        if current_distance <= distances[current_node]:

            for neighbor, weight in enumerate(adjacency_matrix[current_node]):
                if weight > 0:
                    distance = current_distance + weight
                    if distance < distances[neighbor]:
                        distances[neighbor] = distance
                        heapq.heappush(priority_queue, (distance, neighbor))
                        paths[neighbor] = paths[current_node] + [neighbor]

    return paths


def addrule(self, switchname: str, connection) -> None:
    #
    # This function is invoked when a new switch is connected to controller
    # Install table entry to the switch's routing table
    #
    # For more information about POX openflow API,
    # Refer to [POX official document](https://noxrepo.github.io/pox-doc/html/),
    # Especially [ofp_flow_mod - Flow table modification](https://noxrepo.github.io/pox-doc/html/#ofp-flow-mod-flow-table-modification)
    # and [Match Structure](https://noxrepo.github.io/pox-doc/html/#match-structure)
    #
    # your code will be look like:
    #match_arp = of.ofp_match()
    #match_arp.dl_type = 0x0806  

    #match_ipv4 = of.ofp_match()
    #match_ipv4.dl_type = 0x0800  

    #flood_action = [of.ofp_action_output(port=of.OFPP_FLOOD)]

    #flow_mod_arp = of.ofp_flow_mod()
    #flow_mod_arp.match = match_arp
    #flow_mod_arp.actions = flood_action

    #flow_mod_ipv4 = of.ofp_flow_mod()
    #flow_mod_ipv4.match = match_ipv4
    #flow_mod_ipv4.actions = flood_action

    #connection.send(flow_mod_arp)
    #connection.send(flow_mod_ipv4)
    switch_routing_table = self.routing_table.get(switchname, {})
    match_dns = of.ofp_match()
    match_dns.dl_type = 0x0800
    match_dns.nw_proto = 17
    match_dns.tp_dst = 53

    flow_mod_dns = of.ofp_flow_mod()
    flow_mod_dns.match = match_dns
    flow_mod_dns.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
    connection.send(flow_mod_dns)

    for destination, out_port in switch_routing_table.items():

        if destination[0] =="s":
            continue
        match_ipv4 = of.ofp_match()
        match_ipv4.dl_type = 0x0800  
        match_ipv4.nw_dst = self.ip_map[destination]  
        flow_mod_ipv4 = of.ofp_flow_mod()
        flow_mod_ipv4.match = match_ipv4
        flow_mod_ipv4.actions.append(of.ofp_action_output(port=out_port))
        connection.send(flow_mod_ipv4)

        match_arp = of.ofp_match()
        match_arp.dl_type = 0x0806  
        match_arp.nw_dst = self.ip_map[destination]
        flow_mod_arp = of.ofp_flow_mod()
        flow_mod_arp.match = match_arp
        flow_mod_arp.actions.append(of.ofp_action_output(port=out_port))
        connection.send(flow_mod_arp)

from scapy.all import * # you can use scapy in this task
from pox.lib.packet.ipv6 import ipv6
from pox.lib.packet.udp import udp
from pox.lib.packet.dns import dns
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import IPAddr, EthAddr
from struct import unpack,pack

def handlePacket(self, switchname, event, connection):
   # Retrieve how packet is parsed
    # Packet consists of:
    #  - various protocol headers
    #  - one content
    # For example, a DNS over UDP packet consists of following:
    # [Ethernet Header][           Ethernet Body            ]
    #                  [IPv4 Header][       IPv4 Body       ]
    #                               [UDP Header][ UDP Body  ]
    #                                           [DNS Content]
    # POX will parse the packet as following:
    #   ethernet --> ipv4 --> udp --> dns
    # If POX does not know how to parse content, the content will remain as `bytes`
    #     Currently, HTTP messages are not parsed, remaining `bytes`. you should parse it manually.
    # You can find all available packet header and content types from pox/pox/lib/packet/
    packet = event.parsed
    packetfrags = {}
    p = packet
    while p is not None:
        packetfrags[p.__class__.__name__] = p
        if isinstance(p, bytes):
            break
        p = p.next
    print(packet.dump()) # print out received packet
    # How to know protocol header types? see name of class

    udp_layer = packet.find('udp')
    ipv4_layer = packet.find('ipv4')

    if udp_layer and udp_layer.dstport == 53:
        dns_payload = udp_layer.payload
        questions = dns_payload.questions
        domain_name = questions[0].name

        if domain_name == "task5-block.com":
            dns_response = dns()
            dns_response.id = dns_payload.id
            dns_response.flags = 0x8183
            response_header = pack("!HHHHHH",
                dns_payload.id,  # transID
                0x8183,          # response, authoritative, nx dmain
                1,               #1 question
                0,               #0 answers
                0,               # 0 authority records
                0                # 0 additional records
            )

            question_section = b""
            for label in domain_name.split('.'):
                question_section += pack("!B", len(label)) + label.encode()
            question_section += b"\x00"  
            question_section += pack("!HH", questions[0].qtype, questions[0].qclass)

            dns_response_bytes = response_header + question_section
            eth = ethernet()
            eth.src = EthAddr(packet.dst)
            eth.dst = EthAddr(packet.src)
            eth.type = ethernet.IP_TYPE
            
            ip = ipv4()
            ip.srcip = IPAddr(packet.find('ipv4').dstip)
            ip.dstip = IPAddr(packet.find('ipv4').srcip)
            ip.protocol = ipv4.UDP_PROTOCOL

            udp_ = udp()
            udp_.srcport = udp_layer.dstport
            udp_.dstport = udp_layer.srcport
            udp_.next = dns_response_bytes
            
            ip.next = udp_
            eth.next = ip
            msg = of.ofp_packet_out()
            msg.data = eth.pack()
            msg.actions.append(of.ofp_action_output(port=event.port))
            connection.send(msg)
            return


        elif domain_name == "task6-block.com":

                match_dns_response = of.ofp_match()
                match_dns_response.dl_type = 0x0800  
                match_dns_response.nw_proto = 17     
                match_dns_response.tp_src = 53       
                flow_mod_response = of.ofp_flow_mod()
                flow_mod_response.match = match_dns_response
                flow_mod_response.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
                connection.send(flow_mod_response)


                msg = of.ofp_packet_out()
                msg.data = event.ofp
                msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
                connection.send(msg)
                return

        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        connection.send(msg)


    elif udp_layer and udp_layer.srcport == 53: 
        dns_payload = udp_layer.payload
        if hasattr(dns_payload, 'pack'):
            dns_payload = dns_payload.pack()

        if len(dns_payload) >= 12:
            dns_header = unpack("!6H", dns_payload[:12])
            transaction_id, flags, _, ancount, _, _ = dns_header

            if ancount > 0: 
                answer_offset = query_offset
                for i in range(ancount):
                    answer_offset += 12  
                    ip_address = ".".join(map(str, dns_payload[answer_offset:answer_offset + 4]))
                    answer_offset += 4


                    match_http = of.ofp_match()
                    match_http.dl_type = 0x0800  
                    match_http.nw_dst = ip_address
                    match_http.tp_dst = 80  
                    flow_mod_http = of.ofp_flow_mod()
                    flow_mod_http.match = match_http
                    flow_mod_http.actions = []  
                    connection.send(flow_mod_http)


                msg = of.ofp_packet_out()
                msg.data = event.ofp
                msg.actions.append(of.ofp_action_output(port=event.port))
                connection.send(msg)

