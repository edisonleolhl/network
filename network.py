# conding=utf-8
import logging
import copy
import networkx as nx
import time
import json
from webob import Response
from datetime import datetime
from operator import attrgetter
from ryu import cfg
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base.app_manager import lookup_service_brick
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import lldp
from ryu.lib import hub
from ryu.lib import dpid as dpid_lib

from ryu.topology import event, switches
from ryu.topology.switches import Switches
from ryu.topology.switches import LLDPPacket
from ryu.topology.api import get_switch, get_link

import setting

CONF = cfg.CONF

network_instance_name = 'network_api_app'


class NetworkAwareness(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    WEIGHT_MODEL = {'hop': 'hop', 'delay': "delay", "bandwidth": "bandwidth"}
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(NetworkAwareness, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.name = "awareness"
        wsgi = kwargs['wsgi']
        wsgi.register(NetworkController, {network_instance_name: self})

        # network topology datastructure
        self.link_to_port = {}  # (src_dpid,dst_dpid)->(src_port,dst_port)
        self.access_table = {}  # {(sw,port) :[host1_ip]}
        self.switch_port_table = {}  # dpip->port_num -- all port
        self.access_ports = {}  # dpid->port_num -- access_ports = all_port_table - interior_port
        self.interior_ports = {}  # dpid->port_num -- port connected to another switch port
        self.datapaths = {}  # dpid->Datapath Class

        self.graph = nx.DiGraph()
        self.pre_graph = nx.DiGraph()
        self.pre_access_table = {}
        self.pre_link_to_port = {}

        # statistic information of port and link datastructure
        self.port_stats = {}  # maintain a queue (len=5) of port stats to store statistic information
        self.port_speed = {}  # maintain a queue (len=5) [b/s]
        self.flow_stats = {}  # maintain a queue (len=5) of flow stats to store statistic information
        self.flow_speed = {}  # maintain a queue (len=5) [b/s]
        self.stats = {}
        self.port_features = {}  # (dpid,port_no_):(config,state,curr_speed)
        self.free_bandwidth = {}
        self.used_bandwidth = {}
        self.shortest_paths = None
        self.bw_shortest_paths = None
        self.delay_shortest_paths = None
        # delay detector information
        self.echo_latency = {}
        self.sw_module = lookup_service_brick('switches')

        self.weight = self.WEIGHT_MODEL[CONF.weight]
        self.SPOOFING_DEFENCE = setting.SPOOFING_DEFENCE

        # Start a green thread to discover network resource.
        self.discover_thread = hub.spawn(self._discover)

        # self.monitor_thread = hub.spawn(self._monitor)
        # self.save_freebandwidth_thread = hub.spawn(self._save_bw_graph)
        # self.detector_thread = hub.spawn(self._detector)

    def _discover(self):
        """
            Main entry method of colleting network topology information
        """
        i = 0
        self.get_topology(None)
        while True:
            # self.show_topology()
            hub.sleep(setting.DISCOVERY_PERIOD)
            self._monitor()
            # self._save_bw_graph()
            self._detector()
            if i == 5:
                self.get_topology(None)
                i = 0
            i = i + 1

    def _monitor(self):
        """
            Main entry method of monitoring traffic.
        """
        # if self.weight == self.WEIGHT_MODEL['bandwidth']:
        #     self.stats['flow'] = {}
        #     self.stats['port'] = {}
        #     for dp in self.datapaths.values():
        #         self.port_features.setdefault(dp.id, {})
        #         self._request_stats(dp)
        #     hub.sleep(setting.MONITOR_PERIOD)
        #     if self.stats['flow'] or self.stats['port']:
        #         # self.show_stat('flow')
        #         # self.show_stat('port')
        #         hub.sleep(1)
        self.stats['flow'] = {}
        self.stats['port'] = {}
        for dp in self.datapaths.values():
            self.port_features.setdefault(dp.id, {})
            self._request_stats(dp)
        print "used_bandwidth = ", self.used_bandwidth
        # hub.sleep(setting.MONITOR_PERIOD)
        # if self.stats['flow'] or self.stats['port']:
        # self.show_stat('flow')
        # self.show_stat('port')
        # self.format_print(self.used_bandwidth)
        # hub.sleep(1)

    def _save_bw_graph(self):
        """
            Save bandwidth data into networkx graph object.
        """
        # if self.weight == self.WEIGHT_MODEL['bandwidth']:
        #     # self.logger.info("--------------create bw graph and bw_shortest_paths----------------")
        #     if self.used_bandwidth:
        #         self.create_bw_graph(self.used_bandwidth)
        #         self.bw_shortest_paths = nx.shortest_path(self.graph, weight='bandwidth')
        #     hub.sleep(setting.MONITOR_PERIOD)
        # self.logger.info("--------------create bw graph and bw_shortest_paths----------------")
        if self.used_bandwidth:
            self.create_bw_graph(self.used_bandwidth)
            self.bw_shortest_paths = nx.shortest_path(self.graph, weight='bandwidth')
        # hub.sleep(setting.MONITOR_PERIOD)

    def _detector(self):
        """
            Delay detecting functon.
            Send echo request and calculate link delay periodically
        """
        # if self.weight == self.WEIGHT_MODEL['delay']:
        #     # self.logger.info("--------------create delay graph and delay shortest_paths----------------")
        #     self._send_echo_request()
        #     self.create_link_delay()
        #     self.delay_shortest_paths = nx.shortest_path(self.graph, weight='delay')
        #     self.show_delay_statis()
        #     hub.sleep(setting.DELAY_DETECTING_PERIOD)
        self._send_echo_request()
        self.create_link_delay()
        self.show_delay_statis()

    # List the event list should be listened.
    events = [event.EventSwitchEnter,
              event.EventSwitchLeave, event.EventPortAdd,
              event.EventPortDelete, event.EventPortModify,
              event.EventLinkAdd, event.EventLinkDelete]

    @set_ev_cls(events)
    def get_topology(self, ev):
        """
            Get topology info and calculate shortest paths.
        """
        switch_list = get_switch(self.topology_api_app, None)
        self.create_all_port(switch_list)
        self.switches = self.switch_port_table.keys()
        links = get_link(self.topology_api_app)
        self.create_interior_ports(links)
        self.create_access_ports()
        self.get_graph(self.link_to_port.keys())
        self.shortest_paths = dict(nx.all_pairs_dijkstra_path(self.graph))

    def get_shortest_simple_paths(self, src, dst):
        simple_paths = []
        try:
            if self.weight == self.WEIGHT_MODEL['hop']:
                simple_paths = list(nx.shortest_simple_paths(self.graph, src, dst))
            elif self.weight == self.WEIGHT_MODEL['bandwidth']:
                simple_paths = list(nx.shortest_simple_paths(self.graph, src, dst, weight='bandwidth'))
            elif self.weight == self.WEIGHT_MODEL['delay']:
                simple_paths = list(nx.shortest_simple_paths(self.graph, src, dst, weight='delay'))
        except Exception as e:
            print e
        return simple_paths

    def _request_stats(self, datapath):
        """
            Sending request msg to datapath
        """
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def _send_echo_request(self):
        """
            Seng echo request msg to datapath.
        """
        for datapath in self.datapaths.values():
            parser = datapath.ofproto_parser
            echo_req = parser.OFPEchoRequest(datapath,
                                             data="%.12f" % time.time())
            datapath.send_msg(echo_req)
            # Important! Don't send echo request together, Because it will
            # generate a lot of echo reply almost in the same time.
            # which will generate a lot of delay of waiting in queue
            # when processing echo reply in echo_reply_handler.

            hub.sleep(setting.SENDING_ECHO_REQUEST_PERIOD)

    def get_graph(self, link_list):
        """
            Create network graph based on hop (default) by using networkx.
	    Get Adjacency matrix from link_to_port
        """
        for src in self.switches:
            for dst in self.switches:
                if src == dst:
                    self.graph.add_edge(src, dst, weight=0)
                elif (src, dst) in link_list:
                    self.graph.add_edge(src, dst, weight=1)
                # used for Topo_Graph show, but doesn't work in nx.shortest_simple_paths
                # else:
                #     self.graph.add_edge(src, dst, weight=float('inf'))
        return self.graph

    def create_bw_graph(self, bw_dict):
        """
            Adding weight of 'bandwidth' into graph.
        """
        try:
            for src_dpid in self.graph:
                for dst_dpid in self.graph[src_dpid]:
                    if src_dpid == dst_dpid:
                        self.graph[src_dpid][dst_dpid]['bandwidth'] = 0
                    elif (src_dpid, dst_dpid) in self.link_to_port and src_dpid in bw_dict and dst_dpid in bw_dict:
                        (src_port, dst_port) = self.link_to_port[(src_dpid, dst_dpid)]
                        bw_src = bw_dict[src_dpid][src_port]
                        bw_dst = bw_dict[dst_dpid][dst_port]
                        bandwidth = min(bw_src, bw_dst)
                        # add key:value of bandwidth into graph. this is di-graph
                        self.graph[src_dpid][dst_dpid]['bandwidth'] = bandwidth
                    # used for Topo_Graph show, but doesn't work in nx.shortest_simple_paths
                    # else:
                    #     self.graph[src_dpid][dst_dpid]['bandwidth'] = float('inf')
            # self.logger.debug("self.graph[%s][%s]['bandwidth']=%s" %(src_dpid,dst_dpid,self.graph[src_dpid][dst_dpid]['bandwidth']))
            return
        except:
            self.logger.info("Create bw graph exception")
            return

    def create_link_delay(self):
        """
            Adding weight of 'bandwidth' into graph.
        """
        try:
            for src in self.graph:
                for dst in self.graph[src]:
                    if src == dst:
                        self.graph[src][dst]['delay'] = 0
                        continue
                    delay = self.get_delay(src, dst)
                    self.graph[src][dst]['delay'] = delay
                    # self.logger.info("self.graph[%s][%s]['delay']=%s" %(src,dst,self.graph[src][dst]['delay']))
            return
        except:
            self.logger.info("Create delay graph exception")
            return

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
            Collect datapath information.
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.info('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
            Initial operation, send miss-table flow entry to datapaths.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        msg = ev.msg
        self.logger.info("switch:%s connected", datapath.id)

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
            Save flow stats reply info into self.flow_stats.
            Calculate flow speed and Save it.
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.stats['flow'][dpid] = body
        self.flow_stats.setdefault(dpid, {})
        self.flow_speed.setdefault(dpid, {})
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match.get('in_port'),
                                             flow.match.get('ipv4_dst'))):
            # print stat
            key = (stat.match['in_port'], stat.match['ipv4_dst'],
                   stat.instructions[0].actions[0].port)
            value = (stat.packet_count, stat.byte_count,
                     stat.duration_sec, stat.duration_nsec)
            self._save_stats(self.flow_stats[dpid], key, value, 5)

            # Get flow's speed.
            pre = 0
            period = setting.MONITOR_PERIOD
            tmp = self.flow_stats[dpid][key]
            if len(tmp) > 1:
                # get 'the last but one flow's byte_count' as pre
                pre = tmp[-2][1]
                period = self._get_period(tmp[-1][2], tmp[-1][3],
                                          tmp[-2][2], tmp[-2][3])

            speed = self._get_speed(self.flow_stats[dpid][key][-1][1],
                                    pre, period)

            self._save_stats(self.flow_speed[dpid], key, speed, 5)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """
            Save port's stats info
            Calculate port's speed and save it.
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.stats['port'][dpid] = body
        self.free_bandwidth.setdefault(dpid, {})
        self.used_bandwidth.setdefault(dpid, {})
        for stat in sorted(body, key=attrgetter('port_no')):
            port_no = stat.port_no
            if port_no != ofproto_v1_3.OFPP_LOCAL:
                key = (dpid, port_no)
                value = (stat.tx_bytes, stat.rx_bytes, stat.rx_errors,
                         stat.duration_sec, stat.duration_nsec)

                self._save_stats(self.port_stats, key, value, 5)

                # Get port speed.
                pre = 0
                period = setting.MONITOR_PERIOD
                tmp = self.port_stats[key]
                if len(tmp) > 1:
                    # get 'the last but one port stat's tx_bytes and rx_bytes' as pre
                    pre = tmp[-2][0] + tmp[-2][1]
                    # use pre's sec, nsec and now's sec,nsec to calculate period
                    period = self._get_period(tmp[-1][3], tmp[-1][4],
                                              tmp[-2][3], tmp[-2][4])

                speed = self._get_speed(
                    self.port_stats[key][-1][0] + self.port_stats[key][-1][1],
                    pre, period)

                self._save_stats(self.port_speed, key, speed, 5)
                self._save_freebandwidth(dpid, port_no, speed)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        """
            Save port description info.
        """
        msg = ev.msg
        dpid = msg.datapath.id
        ofproto = msg.datapath.ofproto

        config_dict = {ofproto.OFPPC_PORT_DOWN: "Down",
                       ofproto.OFPPC_NO_RECV: "No Recv",
                       ofproto.OFPPC_NO_FWD: "No Farward",
                       ofproto.OFPPC_NO_PACKET_IN: "No Packet-in"}

        state_dict = {ofproto.OFPPS_LINK_DOWN: "Down",
                      ofproto.OFPPS_BLOCKED: "Blocked",
                      ofproto.OFPPS_LIVE: "Live"}

        ports = []
        for p in ev.msg.body:
            ports.append('port_no=%d hw_addr=%s name=%s config=0x%08x '
                         'state=0x%08x curr=0x%08x advertised=0x%08x '
                         'supported=0x%08x peer=0x%08x curr_speed=%d '
                         'max_speed=%d' %
                         (p.port_no, p.hw_addr,
                          p.name, p.config,
                          p.state, p.curr, p.advertised,
                          p.supported, p.peer, p.curr_speed,
                          p.max_speed))

            if p.config in config_dict:
                config = config_dict[p.config]
            else:
                config = "up"

            if p.state in state_dict:
                state = state_dict[p.state]
            else:
                state = "up"

            port_feature = (config, state, p.curr_speed)
            self.port_features[dpid][p.port_no] = port_feature

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        """
            Handle the port status changed event.
        """
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no
        dpid = msg.datapath.id
        ofproto = msg.datapath.ofproto

        reason_dict = {ofproto.OFPPR_ADD: "added",
                       ofproto.OFPPR_DELETE: "deleted",
                       ofproto.OFPPR_MODIFY: "modified", }

        if reason in reason_dict:

            print "switch%d: port %s %s" % (dpid, reason_dict[reason], port_no)
        else:
            print "switch%d: Illeagal port state %s %s" % (port_no, reason)

    @set_ev_cls(ofp_event.EventOFPEchoReply, MAIN_DISPATCHER)
    def echo_reply_handler(self, ev):
        """
            Handle the echo reply msg, and get the latency of link.
        """
        now_timestamp = time.time()
        try:
            latency = now_timestamp - eval(ev.msg.data)
            self.echo_latency[ev.msg.datapath.id] = latency
        except:
            return

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
            If the packet_in is ARP, register the access info and install flow by calculating shortestpath.
	    If the packet_in is ip , install flow by calculating shortestpath.
        """

        msg = ev.msg
        datapath = msg.datapath

        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)

        # ipv4 --> eth_type=2048, arp --> eth_type=2054
        eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
        src_mac = pkt.get_protocols(ethernet.ethernet)[0].src
        # if eth_type != 35020 and eth_type != 34525:
        #    print 'eth_type = ', eth_type
        #    self.logger.info('-Packet_in dpid = %d, in_port = %d-', datapath.id, in_port)

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        lldp_pkt = pkt.get_protocol(lldp.lldp)

        if arp_pkt:
            # self.logger.info("-ARP processing-")
            # Register the access info
            if (datapath.id, in_port) not in self.access_table:
                self.register_access_info(datapath.id, in_port, arp_pkt.src_ip, arp_pkt.src_mac)

            # Detect arp spoofing attack
            elif self.SPOOFING_DEFENCE:
                if (arp_pkt.src_ip, arp_pkt.src_mac) != self.access_table[datapath.id, in_port]:
                    arp_attack_record = open('arp_attack_record.txt', 'a')
                    info1 = "[" + str(
                        datetime.now()) + "]" + "DETECTING ARP SPOOFING ATTACK : " + "switch %s port %s received an illegal packet !!!\n" % (
                                datapath.id, in_port)
                    info2 = "----------------------------Registered host    ip = %s, mac = %s\n" % (
                        self.access_table[datapath.id, in_port][0], self.access_table[datapath.id, in_port][1])
                    info3 = "----------------------------Illegal packet src_ip = %s, src_mac = %s\n\n" % (
                        arp_pkt.src_ip, arp_pkt.src_mac)
                    record = info1 + info2 + info3
                    arp_attack_record.write(record)
                    arp_attack_record.close()
                    self.logger.info("-ARP SPOOFING ATTACK!!!-")
                    return
            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip)
            return

        if ip_pkt:
            # self.logger.info("-IPV4 processing-")
            # Register the access info
            if (datapath.id, in_port) not in self.access_table:
                self.register_access_info(datapath.id, in_port, ip_pkt.src, src_mac)
            # Detect ip spoofing attack
            elif self.SPOOFING_DEFENCE:
                if (ip_pkt.src, src_mac) != self.access_table[datapath.id, in_port]:
                    ip_attack_record = open('ip_attack_record.txt', 'a')
                    info1 = "[" + str(
                        datetime.now()) + "]" + "DETECTING IP SPOOFING ATTACK : " + "switch %s port %s received an illegal packet !!!\n" % (
                                datapath.id, in_port)
                    info2 = "----------------------------Registered host    ip = %s, mac = %s\n" % (
                        self.access_table[datapath.id, in_port][0], self.access_table[datapath.id, in_port][1])
                    info3 = "----------------------------Illegal packet src_ip = %s, src_mac = %s\n\n" % (
                        ip_pkt.src, src_mac)
                    record = info1 + info2 + info3
                    ip_attack_record.write(record)
                    ip_attack_record.close()
                    self.logger.info("-IP SPOOFING ATTACK!!!-")
                    return

            if len(pkt.get_protocols(ethernet.ethernet)):
                self.shortest_forwarding(msg, eth_type, ip_pkt.src, ip_pkt.dst)
                return

        if lldp_pkt:
            try:
                src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)
                # the src_dpid is parsed from msg, the dst_dpid is the PRESENT datapath's id
                dpid = msg.datapath.id
                if self.sw_module is None:
                    self.sw_module = lookup_service_brick('switches')

                # if self.weight == self.WEIGHT_MODEL['delay']:
                #     for port in self.sw_module.ports.keys():
                #         if src_dpid == port.dpid and src_port_no == port.port_no:
                #             lldpdelay = self.sw_module.ports[port].delay
                #             self.graph[src_dpid][dpid]['lldpdelay'] = lldpdelay

                for port in self.sw_module.ports.keys():
                    if src_dpid == port.dpid and src_port_no == port.port_no:
                        lldpdelay = self.sw_module.ports[port].delay
                        self.graph[src_dpid][dpid]['lldpdelay'] = lldpdelay

            except LLDPPacket.LLDPUnknownFormat as e:
                return

    def add_flow(self, dp, p, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=dp, priority=p,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst, table_id=1)
        dp.send_msg(mod)

    def install_flow(self, datapaths, link_to_port, access_table, path,
                     flow_info, buffer_id, data=None, isforward=True):
        ''' 
            Install flow entires for roundtrip: go and back.
            @parameter: path=[dpid1, dpid2...]
                        flow_info=(eth_type, src_ip, dst_ip, in_port)
        '''
        if path is None or len(path) == 0:
            print "Path error!"
            return
        in_port = flow_info[3]
        first_dp = datapaths[path[0]]
        out_port = first_dp.ofproto.OFPP_LOCAL
        back_info = (flow_info[0], flow_info[2], flow_info[1])

        # inter_link
        if len(path) > 2:
            for i in xrange(1, len(path) - 1):
                (pre_dp_port, now_dp_in_port) = self.link_to_port[(path[i - 1], path[i])]
                (now_dp_out_port, lat_dp_port) = self.link_to_port[(path[i], path[i + 1])]
                if now_dp_in_port and now_dp_out_port:
                    src_port, dst_port = now_dp_in_port, now_dp_out_port
                    mid_dp = datapaths[path[i]]
                    self.send_flow_mod(mid_dp, flow_info, src_port, dst_port)
                    self.send_flow_mod(mid_dp, back_info, dst_port, src_port)

        if len(path) > 1:
            # the last datapath flow entry: tor -> host
            last_port_pair = self.link_to_port[(path[-2], path[-1])]
            if last_port_pair is None:
                self.logger.info("last_port_pair is not found")
                return
            src_port = last_port_pair[1]

            (access_dpid, dst_port) = self.get_host_location(flow_info[2])
            if dst_port is None:
                self.logger.info("Last port is not found.")
                return
            last_dp = datapaths[path[-1]]
            self.send_flow_mod(last_dp, flow_info, src_port, dst_port)
            self.send_flow_mod(last_dp, back_info, dst_port, src_port)

            # the first flow entry
            first_port_pair = self.link_to_port[(path[0], path[1])]
            if first_port_pair is None:
                self.logger.info("Port not found in first hop.")
                return
            out_port = first_port_pair[0]
            self.send_flow_mod(first_dp, flow_info, in_port, out_port)
            self.send_flow_mod(first_dp, back_info, out_port, in_port)
            if isforward:
                self.send_packet_out(first_dp, buffer_id, in_port, out_port, data)

        else:
            # src and dst on the same datapath
            (access_dpid, out_port) = self.get_host_location(flow_info[2])
            if out_port is None:
                self.logger.info("Out_port is None in same dp")
                return
            self.send_flow_mod(first_dp, flow_info, in_port, out_port)
            self.send_flow_mod(first_dp, back_info, out_port, in_port)
            if isforward:
                self.send_packet_out(first_dp, buffer_id, in_port, out_port, data)

    def flood(self, msg):
        """
            Flood ARP packet to the access port which has no record of host.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dpid in self.access_ports:
            for port in self.access_ports[dpid]:
                if (dpid, port) not in self.access_table.keys():
                    datapath = self.datapaths[dpid]
                    out = self._build_packet_out(
                        datapath, ofproto.OFP_NO_BUFFER,
                        ofproto.OFPP_CONTROLLER, port, msg.data)
                    datapath.send_msg(out)
                    # print "Flooding msg"

    def arp_forwarding(self, msg, src_ip, dst_ip):
        """ Send ARP packet to the destination host,
            if the dst host record is existed,
            else, flow it to the unknow access port.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # print "ARP src_ip = %s , dst_ip = %s "%(src_ip,dst_ip)
        result = self.get_host_location(dst_ip)
        if result:  # host record in access table.
            datapath_dst, out_port = result[0], result[1]
            datapath = self.datapaths[datapath_dst]
            out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                         ofproto.OFPP_CONTROLLER,
                                         out_port, msg.data)
            datapath.send_msg(out)
            # self.logger.info("Reply ARP to knew host")
        else:
            self.flood(msg)

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Build packet out object.
        """
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out

    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Send packet out packet to assigned datapath.
        """
        out = self._build_packet_out(datapath, buffer_id,
                                     src_port, dst_port, data)
        if out:
            datapath.send_msg(out)

    def send_flow_mod(self, datapath, flow_info, src_port, dst_port):
        """
            Build flow entry, and send it to datapath.
        """
        parser = datapath.ofproto_parser
        actions = []
        actions.append(parser.OFPActionOutput(dst_port))

        match = parser.OFPMatch(
            in_port=src_port, eth_type=flow_info[0],
            ipv4_src=flow_info[1], ipv4_dst=flow_info[2])

        self.add_flow(datapath, 1, match, actions, idle_timeout=15, hard_timeout=0)

    def shortest_forwarding(self, msg, eth_type, ip_src, ip_dst):
        """
            To calculate shortest forwarding path and install them into datapaths.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        src_sw_key = self.get_host_location(ip_src)
        dst_sw_key = self.get_host_location(ip_dst)
        if src_sw_key and dst_sw_key:
            # Path has already calculated, just get it.
            path = self.get_path(src_sw_key[0], dst_sw_key[0], weight=self.weight)
            # self.logger.info("The PATH based on %s between %s<-->%s: %s" % (self.weight, ip_src, ip_dst, path))
            flow_info = (eth_type, ip_src, ip_dst, in_port)
            # install flow entries to datapath along side the path.
            self.install_flow(self.datapaths,
                              self.link_to_port,
                              self.access_table, path,
                              flow_info, msg.buffer_id, msg.data)
        return

    def register_access_info(self, dpid, in_port, ip, mac):
        """
            Register access host info into access table.
        """
        if in_port in self.access_ports[dpid]:
            if (dpid, in_port) in self.access_table:
                print 'pre ip,mac = ', self.access_table[(dpid, in_port)]
                if self.access_table[(dpid, in_port)] == (ip, mac):
                    return
                else:
                    self.access_table[(dpid, in_port)] = (ip, mac)
                    return
            else:
                self.access_table.setdefault((dpid, in_port), None)
                self.access_table[(dpid, in_port)] = (ip, mac)
                return

    def get_path(self, src, dst, weight):
        """
            Get shortest path from network awareness module.
        """
        if weight == self.WEIGHT_MODEL['hop']:
            try:
                paths = self.shortest_paths.get(src).get(dst)
                return paths
            except:
                self.logger.debug('no default(based on hop) shortest_paths!')
                return
        elif weight == self.WEIGHT_MODEL['delay']:
            try:
                paths = self.delay_shortest_paths.get(src).get(dst)
                return paths
            except:
                self.logger.debug('no delay shortest_paths!')
                return
        elif weight == self.WEIGHT_MODEL['bandwidth']:
            try:
                paths = self.bw_shortest_paths.get(src).get(dst)
                return paths
            except:
                self.logger.debug('no bw shortest_paths!')
                return

    def get_host_location(self, host_ip):
        """
            Get host location info:(datapath, port) according to host ip.
            Attention: must invoke 'pingall' command first, so that controller would know all host access info
        """
        if host_ip == '0.0.0.0' or host_ip == '255.255.255.255' or host_ip == '127.0.0.1':
            return None
        for key in self.access_table.keys():
            if self.access_table[key][0] == host_ip:
                return key
        # self.logger.info("%s location is not found." % host_ip)
        return None

    def get_switches(self):
        return self.switches

    def get_links(self):
        return self.link_to_port

    def create_all_port(self, switch_list):
        """
            Create interior_port table and access_port table. 
        """
        for sw in switch_list:
            dpid = sw.dp.id
            self.switch_port_table.setdefault(dpid, set())
            self.interior_ports.setdefault(dpid, set())
            self.access_ports.setdefault(dpid, set())

            for p in sw.ports:
                self.switch_port_table[dpid].add(p.port_no)

    def create_interior_ports(self, link_list):
        """
            Get links` src_port to dst_port  from link_list,
            link_to_port:(src_dpid,dst_dpid)->(src_port,dst_port)
        """
        for link in link_list:
            src = link.src
            dst = link.dst
            self.link_to_port[
                (src.dpid, dst.dpid)] = (src.port_no, dst.port_no)

            # Find the access ports and interior ports
            if link.src.dpid in self.switches:
                self.interior_ports[link.src.dpid].add(link.src.port_no)
            if link.dst.dpid in self.switches:
                self.interior_ports[link.dst.dpid].add(link.dst.port_no)

    def create_access_ports(self):
        """
            access_ports = all_port_table - interior_port
        """
        for sw in self.switch_port_table:
            all_port_table = self.switch_port_table[sw]
            interior_port = self.interior_ports[sw]
            self.access_ports[sw] = all_port_table - interior_port

    def _save_freebandwidth(self, dpid, port_no, speed):
        # Calculate free bandwidth of port and save it.
        port_feature = self.port_features.get(dpid).get(port_no)
        if port_feature:
            capacity = port_feature[2]  # get the port's curr_speed(that means port's max link capacity [kbps])
            free_bw = self._get_free_bw(capacity, speed)  # get free(surplus) bandwidth (capacity minus speed)
            self.free_bandwidth[dpid].setdefault(port_no, None)
            self.used_bandwidth[dpid].setdefault(port_no, None)
            self.free_bandwidth[dpid][port_no] = free_bw  # Mbit/s
            self.used_bandwidth[dpid][port_no] = speed * 8 / 10 ** 6  # Mbit/s
        else:
            self.logger.info("Fail in getting port state")

    def _save_stats(self, _dict, key, value, length):
        if key not in _dict:
            _dict[key] = []
        _dict[key].append(value)

        if len(_dict[key]) > length:
            _dict[key].pop(0)

    def _get_speed(self, now, pre, period):
        if period:
            return (now - pre) / (period)
        else:
            return 0

    def _get_free_bw(self, capacity, speed):
        # bandwidth:Mbit/s
        return max(capacity / 10 ** 3 - speed * 8 / 10 ** 6, 0)

    def get_path_free_bw(self, src_ip, switch_path, dst_ip):
        '''
        free bandwidth of a path depends on the least remaining bandwidth of those ports through the path
        :param src_ip: str type, eg: '10.0.0.1'
        :param switch_path: list type, eg: [1, 2, 5]
        :param dst_ip: str type, eg: '10.0.0.3'
        :return:
        '''
        # already know h1-s1port1, h2-s1port2, h3-s5port1
        # max_bandwidth is defined in mininet topo file
        max_bandwidth = {1: {1: 100, 2: 100, 3: 50, 4: 50, 5: 50},
                         2: {1: 50, 2: 50},
                         3: {1: 50, 2: 50},
                         4: {1: 50, 2: 50},
                         5: {1: 100, 2: 50, 3: 50}}
        free_bw = 100  # init

        src_access_switch, src_access_port = self.get_host_location(src_ip)
        src_access_free_bw = max_bandwidth[src_access_switch][src_access_port] - \
                             self.used_bandwidth[src_access_switch][src_access_port]
        free_bw = min(free_bw, src_access_free_bw)

        for i in range(len(switch_path) - 1):
            port1, port2 = self.link_to_port[(switch_path[i], switch_path[i + 1])]
            port1_free_bw = max_bandwidth[switch_path[i]][port1] - self.used_bandwidth[switch_path[i]][port1]
            free_bw = min(free_bw, port1_free_bw)
            port2_free_bw = max_bandwidth[switch_path[i + 1]][port2] - self.used_bandwidth[switch_path[i + 1]][port2]
            free_bw = min(free_bw, port2_free_bw)

        dst_access_switch, dst_access_port = self.get_host_location(dst_ip)
        dst_access_free_bw = max_bandwidth[dst_access_switch][dst_access_port] - \
                             self.used_bandwidth[dst_access_switch][dst_access_port]
        free_bw = min(free_bw, dst_access_free_bw)

        free_bw = 0 if free_bw < 0 else free_bw
        return free_bw

    def get_path_delay(self, src_ip, switch_path, dst_ip):
        '''
        delay of a path is the sum of all link delay through the path
        :param src_ip: str type, eg: '10.0.0.1'
        :param switch_path: list type, eg: [1, 2, 5]
        :param dst_ip: str type, eg: '10.0.0.3'
        :return:
        '''
        path_delay = 0
        # delay = self.graph[src][dst]['delay']
        for i in range(len(switch_path) - 1):
            path_delay += self.graph[switch_path[i]][switch_path[i + 1]]['delay']
        return path_delay

    def _get_time(self, sec, nsec):
        return sec + nsec / (10 ** 9)

    def _get_period(self, n_sec, n_nsec, p_sec, p_nsec):
        # use four arguments to calculate period
        return self._get_time(n_sec, n_nsec) - self._get_time(p_sec, p_nsec)

    def get_delay(self, src, dst):
        """
            Get link delay.
                        Controller
                        |        |
        src echo latency|        |dst echo latency
                        |        |
                   SwitchA-------SwitchB
                        
                    fwd_delay--->
                        <----reply_delay
            delay = (forward delay + reply delay - src datapath's echo latency
        """
        try:
            fwd_delay = self.graph[src][dst]['lldpdelay']
            re_delay = self.graph[dst][src]['lldpdelay']
            src_latency = self.echo_latency[src]
            dst_latency = self.echo_latency[dst]

            delay = (fwd_delay + re_delay - src_latency - dst_latency) / 2
            return max(delay, 0)
        except:
            return float('inf')

    def format_print(self, d):
        if d:
            print "{"
            for k1 in d.keys():
                print "%12s" % k1 + ":"
                i = 0
                for k2 in d[k1]:
                    i = i + 1
                    if i % 3 == 0 or i == len(d[k1]):
                        print "%16s : %-16s" % (k2, d[k1][k2])
                    else:
                        print "%16s : %-16s" % (k2, d[k1][k2]),
            print "}"

    def show_topology(self):
        print "----------------------------------DataStructure----------------------------------"
        # print "link_to_port = ", self.link_to_port
        # print "access_table = ", self.access_table
        # print "switch_port_table = ", self.switch_port_table
        # print "interior_ports = ", self.interior_ports
        # print "access_ports = ", self.access_ports

        # print "free_bandwidth (Mbit/s)= ",self.free_bandwidth

        if self.weight == self.WEIGHT_MODEL['bandwidth']:
            print "used_bandwidth (Mbit/s)= "
            self.format_print(self.used_bandwidth)

        if self.weight == self.WEIGHT_MODEL['hop']:
            print "hop_shortest_paths = "
            self.format_print(self.shortest_paths)

        if self.weight == self.WEIGHT_MODEL['bandwidth']:
            print "bw_shortest_paths = "
            self.format_print(self.bw_shortest_paths)

        elif self.weight == self.WEIGHT_MODEL['delay']:
            print "delay_shortest_paths = "
            self.format_print(self.delay_shortest_paths)

        # if self.pre_graph != self.graph and setting.TOSHOW:
        #     print "----------------------------------Topo____Graph----------------------------------"
        #     print '%10s' % ("switch"),
        #     for i in self.graph.nodes():
        #         print '%10d' % i,
        #     print ""
        #     for i in self.graph.nodes():
        #         print '%10d' % i,
        #         for j in self.graph[i].values():
        #             print '%10.0f' % j['weight'],
        #         print ""
        #     self.pre_graph = copy.deepcopy(self.graph)

        if self.pre_link_to_port != self.link_to_port and setting.TOSHOW:
            print "----------------------------------Link to  Port----------------------------------"
            print '%10s' % ("switch"),
            for i in self.graph.nodes():
                print '%10d' % i,
            print ""
            for i in self.graph.nodes():
                print '%10d' % i,
                for j in self.graph.nodes():
                    if (i, j) in self.link_to_port.keys():
                        print '%10s' % str(self.link_to_port[(i, j)]),
                    else:
                        print '%10s' % "No-link",
                print ""
            self.pre_link_to_port = copy.deepcopy(self.link_to_port)

        if self.pre_access_table != self.access_table and setting.TOSHOW:
            print "----------------------------------Access___Host----------------------------------"
            print '%10s' % ("switch"), '%12s' % "Host"
            if not self.access_table.keys():
                print "    NO found host"
            else:
                for tup in self.access_table:
                    print '%10d:    ' % tup[0], self.access_table[tup]
            self.pre_access_table = copy.deepcopy(self.access_table)

    def show_stat(self, type):
        '''
            Show statistics info according to data type.
            type: 'port' 'flow'
        '''
        if setting.TOSHOW is False:
            return

        bodys = self.stats[type]
        if (type == 'flow'):
            print"----------------------------------Flow____Stats----------------------------------"
            print('datapath         ''   in-port        ip-dst      '
                  'out-port packets  bytes  flow-speed(B/s)')
            print('---------------- ''  -------- ----------------- '
                  '-------- -------- -------- -----------')
            for dpid in bodys.keys():
                for stat in sorted(
                        [flow for flow in bodys[dpid] if flow.priority == 1],
                        key=lambda flow: (flow.match.get('in_port'),
                                          flow.match.get('ipv4_dst'))):
                    print('%016x %8x %17s %8x %8d %8d %8.1f' % (
                        dpid,
                        stat.match['in_port'], stat.match['ipv4_dst'],
                        stat.instructions[0].actions[0].port,
                        stat.packet_count, stat.byte_count,
                        abs(self.flow_speed[dpid][
                                (stat.match.get('in_port'),
                                 stat.match.get('ipv4_dst'),
                                 stat.instructions[0].actions[0].port)][-1])))
            print '\n'

        if (type == 'port'):
            print"----------------------------------Port____Stats----------------------------------"
            print('datapath             port   ''rx-pkts  rx-bytes rx-error '
                  'tx-pkts  tx-bytes tx-error  port-speed(B/s)'
                  ' current-capacity(Kbps)  '
                  'port-stat   link-stat')
            print('----------------   -------- ''-------- -------- -------- '
                  '-------- -------- -------- '
                  '----------------  ----------------   '
                  '   -----------    -----------')
            format = '%016x %8x %8d %8d %8d %8d %8d %8d %8.1f %16d %16s %16s'
            for dpid in bodys.keys():
                for stat in sorted(bodys[dpid], key=attrgetter('port_no')):
                    if stat.port_no != ofproto_v1_3.OFPP_LOCAL:
                        print(format % (
                            dpid, stat.port_no,
                            stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                            stat.tx_packets, stat.tx_bytes, stat.tx_errors,
                            abs(self.port_speed[(dpid, stat.port_no)][-1]),
                            self.port_features[dpid][stat.port_no][2],
                            self.port_features[dpid][stat.port_no][0],
                            self.port_features[dpid][stat.port_no][1]))
            print '\n'

    def show_delay_statis(self):
        # if setting.TOSHOW:
        #     print"---------------------------------link____delay----------------------------------"
        #     self.logger.info("\nsrc_dpid   dst_dpid      delay")
        #     self.logger.info("-------------------------------")
        #     for src in self.graph:
        #         for dst in self.graph[src]:
        #             delay = self.graph[src][dst]['delay']
        #             self.logger.info("   %s <------> %s      : %-20s" % (src, dst, delay))
        print"---------------------------------link____delay----------------------------------"
        self.logger.info("\nsrc_dpid   dst_dpid      delay")
        self.logger.info("-------------------------------")
        for src in self.graph:
            for dst in self.graph[src]:
                delay = self.graph[src][dst]['delay']
                self.logger.info("   %s <------> %s      : %-20s" % (src, dst, delay))


class NetworkController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(NetworkController, self).__init__(req, link, data, **config)
        self.network_app = data[network_instance_name]

    # for administrator
    # command example
    #
    #   curl -X PUT -d '{"weight":"hop"}' http://127.0.0.1:8080/network/weight
    @route('network', '/network/weight', methods=['PUT'])
    def change_shortest_path_weight_api(self, req, **kwargs):
        network = self.network_app
        try:
            if req.body:
                new_weight = eval(req.body)['weight']
                print req.body
        except ValueError:
            return Response(status=400)
        if new_weight not in self.network_app.WEIGHT_MODEL:
            return Response(status=404)
        try:
            self.network_app.weight = self.network_app.WEIGHT_MODEL[new_weight]
            body = json.dumps(self.network_app.weight)
            return Response(content_type='application/json', body=body)
        except Exception as e:
            return Response(status=500)

    @route('network', '/network/spoofing_defence', methods=['PUT'])
    def spoofing_defence_api(self, req, **kwargs):
        network = self.network_app
        try:
            if req.body:
                flag = eval(req.body)['spoofing_defence']
                print req.body
        except ValueError:
            return Response(status=400)
        if flag not in ['enable', 'disable']:
            return Response(status=404)
        elif flag == 'enable':
            self.network_app.SPOOFING_DEFENCE = True
            print "Spoofing Defence enable !"
        else:
            self.network_app.SPOOFING_DEFENCE = False
            print "Spoofing Defence disable !"
        try:
            info = "Spoofing Defence " + flag + "!"
            body = json.dumps(info)
            return Response(content_type='application/json', body=body)
        except Exception as e:
            return Response(status=500)

    # only for user(host terminal)
    # command example:
    #
    #   curl -X GET http://<nat0ip>:8080/network/querypath
    #
    #  no parameters, easy to use
    @route('network', '/network/querypath', methods=['GET'])
    def user_query_path_api(self, req, **kwargs):
        network = self.network_app
        user_ip = req.client_addr
        nat0_ip = req.host.split(':')[0]
        user_access_key = self.network_app.get_host_location(user_ip)
        print user_ip, user_access_key
        try:
            available_path = {}
            if user_ip == '127.0.0.1':
                return Response(content_type='application/json',
                                body=json.dumps(('ERROR: Only allow user host to query path !')))
            else:
                # a user wants to know the path between all other host
                # notice that the structrue of 'access_table' is sth like ' {(dpid, port_num):(ip, mac), ...}'
                for dst_access_key, dst in self.network_app.access_table.items():
                    if dst[0] != nat0_ip and user_access_key != dst_access_key:
                        src_dst_str = user_ip + '-' + dst[0]
                        available_path[src_dst_str] = self.network_app.get_shortest_simple_paths(user_access_key[0],
                                                                                                 dst_access_key[0])

            print "available_path = ", available_path
            body = json.dumps(available_path)
            return Response(content_type='application/json', body=body)
        except Exception as e:
            print e
            return Response(status=500)

    # only for user(host terminal)
    # command example:
    #
    #   curl -X PUT -d '{"dst_ip":"10.0.0.3", "path":"[1,3,4,5]"}' http://<nat0ip>:8080/network/choosepath
    #
    # notice that there is no blank space in [1,3,4,5],
    # otherwise decode error, status code 404
    @route('network', '/network/choosepath', methods=['PUT'])
    def user_choose_path_api(self, req, **kwargs):
        network = self.network_app
        user_ip = req.client_addr
        nat0_ip = req.host.split(':')[0]
        user_access_key = self.network_app.get_host_location(user_ip)
        print "user info = ", user_ip, user_access_key

        available_path = {}
        try:
            if user_ip == '127.0.0.1':
                return Response(content_type='application/json',
                                body=json.dumps(('ERROR: Only allow user host to query path !')))
            else:
                # a user wants to know the path between all other host
                # notice that the structrue of 'access_table' is sth like '(dpid, port_num)'
                for dst_access_key, dst in self.network_app.access_table.items():
                    if dst[0] != nat0_ip and user_access_key != dst_access_key:
                        src_dst_str = user_ip + '-' + dst[0]
                        available_path[src_dst_str] = self.network_app.get_shortest_simple_paths(user_access_key[0],
                                                                                                 dst_access_key[0])
            print "available_path = ", available_path
        except Exception as e:
            return Response(status=500)

        # guarantee legal parameters
        try:
            if req.body:
                dst_ip = eval(req.body)['dst_ip']
                path_raw = eval(req.body)['path']  # path_raw = '[1,3,4,5]'
                path = path_raw.strip('[]').split(',')  # path = ['1','3','4','5']
                for i in range(len(path)):
                    path[i] = int(path[i])
                print "req.body.dst_ip = ", dst_ip  # dst_ip = 10.0.0.3
                print "req.body.path = ", path  # path = [1, 3, 4, 5]
        except ValueError:
            print "Parameters illegal !"
            return Response(status=400)

        # guarantee legal path
        src_dst_str = user_ip + '-' + dst_ip
        if path not in available_path[src_dst_str]:
            if path[-1] != self.network_app.get_host_location(dst_ip)[0]:
                return Response(status=404)

        try:
            buffer_id = 0xffffffff  # no buffer
            flow_info = (2048, user_ip, dst_ip, user_access_key[1])
            self.network_app.install_flow(self.network_app.datapaths, self.network_app.link_to_port,
                                          self.network_app.access_table, path, flow_info, buffer_id, isforward=False)
            body = json.dumps('choose completed !')
            return Response(content_type='application/json', body=body)
        except Exception as e:
            print e
            return Response(status=500)

    # only for user(host terminal)
    # command example:
    #
    #   curl -X POST -d '{"path":"10.0.0.1-->s1-->s2-->s5-->10.0.0.3"}' http://<nat0ip>:8080/network/query-remaining-bandwidth
    #
    @route('network', '/network/query-remaining-bandwidth', methods=['POST'])
    def user_query_remaining_bandwidth_api(self, req, **kwargs):
        network = self.network_app
        user_ip = req.client_addr
        nat0_ip = req.host.split(':')[0]
        user_access_key = self.network_app.get_host_location(user_ip)
        print user_ip, user_access_key

        try:
            if user_ip == '127.0.0.1':
                return Response(content_type='application/json',
                                body=json.dumps(('ERROR: Only allow user host to query path !')))
        except Exception as e:
            print e
            return Response(status=500)

        # guarantee legal parameters
        try:
            if req.body:
                path_raw = eval(req.body)['path']
                print 'path_raw = ', path_raw  # path_raw = '10.0.0.1-->s1-->s2-->s5-->10.0.0.3'
                src_ip = path_raw.replace('s', '').split('-->')[0]  # src_ip = '10.0.0.1'
                switch_path = path_raw.replace('s', '').split('-->')[1:-1]  # switch_path = ['1', '2', '5']
                switch_path = [int(x) for x in switch_path]  # switch_path = [1, 2, 5]
                dst_ip = path_raw.replace('s', '').split('-->')[-1]  # dst_ip = '10.0.0.3'
                free_bw = self.network_app.get_path_free_bw(src_ip, switch_path, dst_ip)
                print "current path free bandwidth = ", free_bw
                data = {"free_bw": free_bw}
                body = json.dumps(data)
                return Response(content_type='application/json', body=body)
        except ValueError:
            print "Parameters illegal !"
            return Response(status=400)

    # only for user(host terminal)
    # command example:
    #
    #   curl -X POST -d '{"path":"10.0.0.1-->s1-->s2-->s5-->10.0.0.3"}' http://<nat0ip>:8080/network/query-delay
    #
    @route('network', '/network/query-delay', methods=['POST'])
    def user_query_delay_api(self, req, **kwargs):
        network = self.network_app
        user_ip = req.client_addr
        nat0_ip = req.host.split(':')[0]
        user_access_key = self.network_app.get_host_location(user_ip)
        print user_ip, user_access_key

        try:
            if user_ip == '127.0.0.1':
                return Response(content_type='application/json',
                                body=json.dumps(('ERROR: Only allow user host to query path !')))
        except Exception as e:
            print e
            return Response(status=500)

        # guarantee legal parameters
        try:
            if req.body:
                path_raw = eval(req.body)['path']
                print 'path_raw = ', path_raw  # path_raw = '10.0.0.1-->s1-->s2-->s5-->10.0.0.3'
                src_ip = path_raw.replace('s', '').split('-->')[0]  # src_ip = '10.0.0.1'
                switch_path = path_raw.replace('s', '').split('-->')[1:-1]  # switch_path = ['1', '2', '5']
                switch_path = [int(x) for x in switch_path]  # switch_path = [1, 2, 5]
                dst_ip = path_raw.replace('s', '').split('-->')[-1]  # dst_ip = '10.0.0.3'
                # free_bw = self.network_app.get_path_free_bw(src_ip, switch_path, dst_ip)
                path_delay = self.network_app.get_path_delay(src_ip, switch_path, dst_ip)
                print "current path delay = ", path_delay
                data = {"path_delay": path_delay}
                body = json.dumps(data)
                return Response(content_type='application/json', body=body)
        except ValueError:
            print "Parameters illegal !"
            return Response(status=400)
