from __future__ import print_function
import networkx as nx
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import tcp
from ryu.lib import hub
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.lib.packet import ether_types
from collections import defaultdict
from ryu.topology.api import get_host, get_link, get_switch
from threading import Semaphore
import time

ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ARP = arp.arp.__name__
class Workload(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(Workload, self).__init__(*args, **kwargs)
    
        self.COUNT_WORKLOAD_INTERVAL = 3
        self.PRINT_WORKLOAD_INTERVAL = 5
        self.UTAH_IP_ADDR = '10.0.0.25'
        self.ILLI_IP_ADDR = '10.0.0.10'
        self.TINK_IP_ADDR = '10.0.0.21'

        self.topology_api_app = self
        self.datapaths = {} # dpid: datapath
        self.port_stats = {} # (dpid,port_no):a list of port_stats
        self.link_info = {}  # (s1, s2): s1.port
        self.port_link = {} # s1,port:s1,s2
        self.port_info = {}  # dpid: (ports linked hosts)
        self.topo_map_edit_lock = Semaphore()
        self.topo_map = nx.Graph()
        self.workload_thread = hub.spawn(self._count_workload)
        # self.print_workload_thread = hub.spawn(self.print_port_stats)
        self.mac_to_port = {}
        self.mac_ip_inport = {}
        self.sw = {} # use it to avoid arp loop
        self.hosts = {} # host_ip: dpid
        self.weight = 'hop'

        # you need to store workload of every port here
        self.last_port_stats = {} # (dpid, port_no): {bytes: total_bytes, time: total_time}
        self.workload = {} # dpid: {port_no : work_load}

        self.last_handle_ipv4 = {} # (srcip, dstip): timestamp


    def _count_workload(self):
        while True:
            for dp in self.datapaths.values():
                self._send_request(dp)
            self.get_topology(None)
            hub.sleep(self.COUNT_WORKLOAD_INTERVAL)

    def _send_request(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
        
    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
        
    def add_flow(self, dp, p, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=p,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) 
    def switch_features_handler(self, ev): 
        msg = ev.msg 
        dp = msg.datapath 
        ofp = dp.ofproto 
        parser = dp.ofproto_parser
        match = parser.OFPMatch() 
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,ofp.OFPCML_NO_BUFFER)] 
        self.add_flow(dp, 0, match, actions)

    def calc_used_bandwidth(self, key, bytes, time):
        dpid, port_no = key
        if key in self.last_port_stats:
            lbytes, ltime = self.last_port_stats[key]
            self.workload[dpid][port_no] = (bytes - lbytes) / (time - ltime) * 8 * 1e-6 # Mbit/s
        else:
            # lbytes, ltime both are 0 initially
            self.workload[dpid][port_no] = bytes / time * 8 * 1e-6 # Mbit/s
        # update
        self.last_port_stats[key] = (bytes, time)
    
    def print_port_stats(self):
        while True:
            print("=" * 80)
            for dp in self.datapaths.values():
                dpid = dp.id
                if dpid == 20 or dpid == 25:
                    print("switch id dpid: %s :" % dpid, ["<port: %s workload: %s>" % (port_no, workload) for port_no, workload in self.workload[dpid].items()])
            hub.sleep(self.PRINT_WORKLOAD_INTERVAL)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.workload.setdefault(dpid, {})

        # you need to code here to finish mission1
        # of course, you can define new function as you wish

        for stat in sorted(body, key=attrgetter('port_no')):
            port_no = stat.port_no
            if port_no != ofproto_v1_3.OFPP_LOCAL:
                key = (dpid, port_no)
                total_bytes = stat.tx_bytes + stat.rx_bytes
                total_time  = stat.duration_sec + 1e-9 * stat.duration_nsec

                self.calc_used_bandwidth(key, total_bytes, total_time)

                # value = (stat.tx_bytes, stat.rx_bytes, total_bytes,
                        # stat.duration_sec, stat.duration_nsec, total_time)
                # print(key, end=':')
                # print(value)
                # print("")

        # self.print_port_stats(dpid)


############################detect topology############################
    def get_topology(self, ev):
        """
            Gett topology info to calculate shortest paths.
        """
        _hosts, _switches, _links = None, None, None
        hosts = get_host(self)
        switches = get_switch(self)
        links = get_link(self)

        # update topo_map when topology change
        if [str(x) for x in hosts] == _hosts and [str(x) for x in switches] == _switches and [str(x) for x in
                                                                                              links] == _links:
            return 
        _hosts, _switches, _links = [str(x) for x in hosts], [str(x) for x in switches], [str(x) for x in links]

        self.topo_map_edit_lock.acquire()
        self.topo_map = nx.Graph()
        for switch in switches:
            self.port_info.setdefault(switch.dp.id, set())
            # record all ports
            for port in switch.ports:
                self.port_info[switch.dp.id].add(port.port_no)

        for host in hosts:
            # take one ipv4 address as host id
            if host.ipv4:
                self.link_info[(host.port.dpid, host.ipv4[0])] = host.port.port_no
                self.topo_map.add_edge(host.ipv4[0], host.port.dpid, hop=1, delay=0, is_host=True)
                if not host.ipv4[0] in self.hosts:
                    print("host %s: dpid %s" % (host.ipv4[0], host.port.dpid))
                self.hosts[host.ipv4[0]] = host.port.dpid
                

        for link in links:
            # delete ports linked switches
            self.port_info[link.src.dpid].discard(link.src.port_no)
            self.port_info[link.dst.dpid].discard(link.dst.port_no)

            # s1 -> s2: s1.port, s2 -> s1: s2.port
            self.port_link[(link.src.dpid, link.src.port_no)] = (link.src.dpid, link.dst.dpid)
            self.port_link[(link.dst.dpid, link.dst.port_no)] = (link.dst.dpid, link.src.dpid)

            self.link_info[(link.src.dpid, link.dst.dpid)] = link.src.port_no
            self.link_info[(link.dst.dpid, link.src.dpid)] = link.dst.port_no
            self.topo_map.add_edge(link.src.dpid, link.dst.dpid, hop=1, is_host=False)
        self.topo_map_edit_lock.release()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        dpid = dp.id
        in_port = msg.match['in_port']

        self.mac_to_port.setdefault(dpid, {})
        self.mac_ip_inport.setdefault(dpid, {})

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        pkt_type = eth_pkt.ethertype
        # layer 2 self-learning
        dst_mac = eth_pkt.dst
        src_mac = eth_pkt.src

        if isinstance(arp_pkt, arp.arp):
            self.handle_arp(msg, in_port, dst_mac, src_mac, pkt, pkt_type)

        if isinstance(ipv4_pkt, ipv4.ipv4):
            self.handle_ipv4(msg, ipv4_pkt.src, ipv4_pkt.dst, pkt_type)

############################deal with loop############################
    def handle_arp(self, msg, in_port, dst, src, pkt, pkt_type):
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        dpid = dp.id
        in_port = msg.match['in_port']
        src_ip = pkt.get_protocol(arp.arp).src_ip
        dst_ip = pkt.get_protocol(arp.arp).dst_ip
        if(self.mac_ip_inport[dpid].has_key(src) and self.mac_ip_inport[dpid][src].has_key(dst_ip) and self.mac_ip_inport[dpid][src][dst_ip] != in_port):
            # drop it
            # self.logger.info('%s: ARP packet query %s from host %s port %s(ori: %s) has dropped because of loop.', dpid, dst_ip, src, in_port, self.mac_ip_inport[dpid][src][dst_ip])
            return
        # add record and flood it
        if(not self.mac_ip_inport[dpid].has_key(src)):
            self.mac_ip_inport[dpid][src] = {}
        self.mac_ip_inport[dpid][src][dst_ip] = in_port
        # self.logger.info('%s: ARP packet query %s from host %s port %s first flood.', dpid, dst_ip, src, in_port)

        # learn src2port mapping
        self.mac_to_port[dpid][src] = in_port
        
        # find out whether dst has a mapping
        if(self.mac_to_port[dpid].has_key(dst)):
            # use learned mapping
            dst_port = self.mac_to_port[dpid][dst]
            
            # add flow table
            match = parser.OFPMatch(in_port=in_port, eth_type=pkt_type, eth_dst=dst)
            actions = [parser.OFPActionOutput(dst_port)]
            self.add_flow(dp, 1, match, actions, 10, 30)

            # send packet-out
            actions = [parser.OFPActionOutput(dst_port)]
            out = parser.OFPPacketOut(
                datapath=dp, buffer_id=msg.buffer_id,
                in_port=msg.match['in_port'],actions=actions, data=msg.data)
            dp.send_msg(out)

            # self.logger.info('%s: packet: %s to %s from port %s to port %s', dpid, src, dst, in_port, dst_port)
        else:
            # have to flood
            actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            out = parser.OFPPacketOut(
                datapath=dp, buffer_id=msg.buffer_id, 
                in_port=msg.match['in_port'],actions=actions, data=msg.data)
            dp.send_msg(out)
        
            # self.logger.info('%s: packet: %s to %s from port %s to port ? (flooded)', dpid, src, dst, in_port)


############################get shortest(hop) path############################
    def handle_ipv4(self, msg, src_ip, dst_ip, pkt_type):
        parser = msg.datapath.ofproto_parser

        now = time.time()
        if (src_ip, dst_ip) in self.last_handle_ipv4 and now - self.last_handle_ipv4[(src_ip, dst_ip)] < 2.0:
            return # don't calc same route multiple times

        all_path = self.available_path(src_ip, dst_ip)
        if not all_path:
            return

        dpid_path = all_path[0]
        self.logger.info('%s path(s) in total:' % len(all_path))
        self.show_all_path(src_ip, dst_ip, all_path)

        self.logger.info('selected:')
        # get port path:  h1 -> in_port, s1, out_port -> h2
        port_path = []
        for i in range(1, len(dpid_path) - 1):
            in_port = self.link_info[(dpid_path[i], dpid_path[i - 1])]
            out_port = self.link_info[(dpid_path[i], dpid_path[i + 1])]
            port_path.append((in_port, dpid_path[i], out_port))
        self.show_path(src_ip, dst_ip, port_path)
        self.logger.info('')

        # send flow mod
        for node in port_path:
            in_port, dpid, out_port = node
            self.send_flow_mod(parser, dpid, pkt_type, src_ip, dst_ip, in_port, out_port, 2, 30)
            self.send_flow_mod(parser, dpid, pkt_type, dst_ip, src_ip, out_port, in_port, 2, 30)

        self.last_handle_ipv4[(src_ip, dst_ip)] = now

        # send packet_out
        _, dpid, out_port = port_path[-1]
        dp = self.datapaths[dpid]
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
        dp.send_msg(out)

    def available_path(self, src, dst):
        self.topo_map_edit_lock.acquire()
        paths = []
        if (src, dst) == (self.UTAH_IP_ADDR, self.ILLI_IP_ADDR) or \
           (dst, src) == (self.UTAH_IP_ADDR, self.ILLI_IP_ADDR):
            try:
                try:
                    self.topo_map.remove_edge(self.hosts[src], self.hosts[dst])
                except nx.NetworkXError:
                    # no edge between two hosts
                    pass

                paths_from_src_to_tinker = list(nx.shortest_simple_paths(self.topo_map, src, self.TINK_IP_ADDR, weight='hop'))
                paths_from_tinker_to_dst = list(nx.shortest_simple_paths(self.topo_map, self.TINK_IP_ADDR, dst, weight='hop'))
                for path1 in paths_from_src_to_tinker:
                    for path2 in paths_from_tinker_to_dst:
                        paths.append(path1[:-2] + path2[1:])
                        # self.logger.info(str(path1[:-1] + path2[1:]))
                def hop_cmp(x, y):
                    if len(x) <= len(y):
                        return -1
                    else:
                        return 1
                paths = sorted(paths, hop_cmp)
                self.topo_map.add_edge(self.hosts[src], self.hosts[dst], hop=1, is_host=False)
            except Exception as e:
                self.logger.info(e)
                # self.logger.info('host not find/no path')
        else:
            try:
                paths = list(nx.shortest_simple_paths(self.topo_map, src, dst, weight='hop'))
            except:
                self.logger.info('host not find/no path')

        self.topo_map_edit_lock.release()
        return paths

    def shortest_path(self, src, dst, weight='hop'):
        try:
            paths = list(nx.shortest_simple_paths(self.topo_map, src, dst, weight=weight))
            return paths[0]
        except:
            self.logger.info('host not find/no path')

    def send_flow_mod(self, parser, dpid, pkt_type, src_ip, dst_ip, in_port, out_port, idle_timeout=10, hard_timeout=120):
        dp = self.datapaths[dpid]
        match = parser.OFPMatch(
            in_port=in_port, eth_type=pkt_type, ipv4_src=src_ip, ipv4_dst=dst_ip)
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(dp, 5, match, actions, idle_timeout, hard_timeout)

    def show_path(self, src, dst, port_path):
        self.logger.info('path: {} -> {}'.format(src, dst))
        path = src + ' -> '
        for node in port_path:
            path += '{}:s{}:{}'.format(*node) + ' -> '
        path += dst
        self.logger.info(path)

    def show_all_path(self, src, dst, paths):
        self.logger.info('path: {} -> {}'.format(src, dst))
        for path in paths:
            port_path = []
            msg = src + ' -> '
            for i in range(1, len(path) - 1):
                in_port = self.link_info[(path[i], path[i - 1])]
                out_port = self.link_info[(path[i], path[i + 1])]
                port_path.append((in_port, path[i], out_port))
            for node in port_path:
                msg += '{}:s{}:{}'.format(*node) + ' -> '
            msg += dst
            self.logger.info(msg)