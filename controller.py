from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import lldp
from ryu.lib.packet import arp

import numpy as np
import time
import networkx as nx

SWITCH_NO = 14



class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.logger.setLevel("DEBUG")
        self.mac_to_port = {}  # arp
        self.datapaths = {}    # save switches information
        self.port_number = {}
        self.sw_port_to_sw_port = {}
        self.start_ij = np.zeros(SWITCH_NO)  # timer
        self.delay_ij = np.zeros((SWITCH_NO,SWITCH_NO))

        self.G = nx.Graph()  # networkx

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # install trap flow entry
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_LLDP)
        self.add_flow(datapath, 0, match, actions,hard_timeout=1)

        # get switch's port information
        self.send_port_stats_request(datapath)

        # add node (networkx)
        self.G.add_node(datapath.id)

    def send_port_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        # use OFPPortDescStatsRequest to get the mac address of switch port
        req = ofp_parser.OFPPortDescStatsRequest(datapath, 0, ofp.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.port_number.setdefault(datapath.id,{})
        for stat in ev.msg.body:
            if stat.port_no < ofproto.OFPP_MAX:
                self.port_number[datapath.id][stat.port_no] = stat.hw_addr


    def send_lldp_packet(self, datapath, port_no, hw_addr):
        ofp = datapath.ofproto
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_LLDP,src=hw_addr ,dst=lldp.LLDP_MAC_NEAREST_BRIDGE))
        tlv_chassis_id = lldp.ChassisID(subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED, chassis_id=bytes([datapath.id]))
        tlv_port_id = lldp.PortID(subtype=lldp.PortID.SUB_LOCALLY_ASSIGNED, port_id=bytes([port_no]))
        tlv_ttl = lldp.TTL(ttl=10)
        tlv_end = lldp.End()
        tlvs = (tlv_chassis_id, tlv_port_id, tlv_ttl, tlv_end)
        lldp_pkt = lldp.lldp(tlvs)
        pkt.add_protocol(lldp_pkt)
        pkt.serialize()
        data = pkt.data
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(port=port_no)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)    

    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]


    def add_flow(self, datapath, priority, match, actions, buffer_id=None,hard_timeout=0,flags=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst,hard_timeout=hard_timeout,flags=ofproto_v1_3.OFPFF_SEND_FLOW_REM)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,hard_timeout=hard_timeout,flags=ofproto_v1_3.OFPFF_SEND_FLOW_REM)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            # ignore IPV6 packet
            return
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:  # dump flow Packet-In
            pkt_lldp = pkt.get_protocol(lldp.lldp)
            self.estimate_link_delay(datapath,pkt_lldp)
            self.setup_topo(datapath, in_port, pkt_lldp)
            return
        print(pkt)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            pkt_arp = pkt.get_protocol(arp.arp)
            print(pkt_arp)
            src = pkt_arp.src_ip
            dst = pkt_arp.dst_ip
            if len(src) == 9:
                src = int(10*int(src[7]) + int(src[8]))
            else:
                src = int(src[7])
            if len(dst) == 9:
                dst = int(10*int(dst[7]) + int(dst[8]))
            else:
                dst = int(dst[7])
            path = nx.shortest_path(self.G,src,dst)
            print("path   :  ",path)
            
            dst = eth.dst
            src = eth.src

            dpid = format(datapath.id, "d").zfill(16)
            self.mac_to_port.setdefault(dpid, {})

            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port
            print(self.mac_to_port)
            out_port = None
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                for i in range(len(path)):
                    if i == len(path) - 1 and path[i] == datapath.id:
                        out_port = 1
                        actions = [parser.OFPActionOutput(out_port)]
                    elif path[i] == datapath.id:
                        out_port = self.sw_port_to_sw_port[path[i]][path[i + 1]]
                        actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(eth_dst=dst, eth_src=src)
            actions = [parser.OFPActionOutput(out_port)]
            # install a flow to avoid packet_in next time
            if dst != "ff:ff:ff:ff:ff:ff" and src != "ff:ff:ff:ff:ff:ff":
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 100, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 100, match, actions)
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

        if eth.ethertype == 0x0800:
            dst = eth.dst
            src = eth.src
            dpid = format(datapath.id, "d").zfill(16)
            self.mac_to_port[dpid][src] = in_port
            out_port = self.mac_to_port[dpid][dst]
            match = parser.OFPMatch(eth_dst=dst, eth_src=src)
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 100, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 100, match, actions)
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
    
    def setup_topo(self, datapath, port, pkt_lldp):
        i = int.from_bytes(pkt_lldp.tlvs[0].chassis_id,"big")
        j = datapath.id
        self.G.add_edge(i,j)
        self.sw_port_to_sw_port.setdefault(j,{})
        self.sw_port_to_sw_port[j][i] = port
    

    def estimate_link_delay(self,datapath,pkt_lldp):
        i = int.from_bytes(pkt_lldp.tlvs[0].chassis_id,"big") - 1
        j = datapath.id - 1
        self.delay_ij[i][j] = float(time.time()) - self.start_ij[i]
        #self.logger.debug(self.delay_ij)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # set timer start_ij
        self.start_ij[datapath.id - 1] = float(time.time())

        # for every port of sw_i, the controller packs a LLDP packet 
        # and sends it to swi using OpenFlow Packet-Out message.
        for port_no in range(1,len(self.port_number[datapath.id]) + 1):
            hw_addr = self.port_number[datapath.id][port_no]
            self.send_lldp_packet(datapath, port_no, hw_addr)

        # re-installs the dummy flow entry
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_LLDP)
        self.add_flow(datapath, 0, match, actions,hard_timeout=1)



