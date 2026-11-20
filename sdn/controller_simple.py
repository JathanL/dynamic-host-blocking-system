from collections import Counter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp
from ryu.lib import hub

PORT = 5000     # the server port we protect
LIMIT = 15      # more than this many connections = suspicious
EVERY = 5       # check the switch every 5 seconds


class SimpleBlocker(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.switch = None          # we have only one switch (s1)
        self.blocklist = []         # IPs we have blocked
        self.mac_of = {}            # IP -> MAC address of the host that used it
        hub.spawn(self.check_loop)  # background loop that asks for statistics

    def send_rule(self, priority, match, actions, idle=0):
        parser = self.switch.ofproto_parser
        ofp = self.switch.ofproto
        if actions:
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        else:
            inst = []               # no actions = DROP
        rule = parser.OFPFlowMod(datapath=self.switch, priority=priority,
                                 match=match, instructions=inst, idle_timeout=idle)
        self.switch.send_msg(rule)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_connected(self, ev):
        self.switch = ev.msg.datapath
        parser = self.switch.ofproto_parser
        ofp = self.switch.ofproto
        # table-miss rule: unknown packets go to the controller
        to_controller = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.send_rule(0, parser.OFPMatch(), to_controller)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_arrived(self, ev):
        msg = ev.msg
        parser = self.switch.ofproto_parser
        ofp = self.switch.ofproto
        normal = [parser.OFPActionOutput(ofp.OFPP_NORMAL)]   # let the switch forward normally

        pkt = packet.Packet(msg.data)
        ip = pkt.get_protocol(ipv4.ipv4)
        t = pkt.get_protocol(tcp.tcp)
        eth = pkt.get_protocol(ethernet.ethernet)
        if ip and t:                                         # a TCP packet: make a rule for it
            self.mac_of[ip.src] = eth.src                    # remember which MAC owns this IP
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=6,
                                    ipv4_src=ip.src, ipv4_dst=ip.dst,
                                    tcp_src=t.src_port, tcp_dst=t.dst_port)
            self.send_rule(10, match, normal, idle=10)

        out = parser.OFPPacketOut(datapath=self.switch, buffer_id=msg.buffer_id,
                                  in_port=msg.match['in_port'], actions=normal,
                                  data=msg.data)
        self.switch.send_msg(out)

    def check_loop(self):
        while True:
            hub.sleep(EVERY)
            if self.switch:
                parser = self.switch.ofproto_parser
                self.switch.send_msg(parser.OFPFlowStatsRequest(self.switch))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def stats_arrived(self, ev):
        parser = self.switch.ofproto_parser
        counts = Counter()
        for flow in ev.msg.body:
            if flow.priority == 10 and flow.match.get('tcp_dst') == PORT:
                counts[flow.match['ipv4_src']] += 1          # one rule = one connection

        for ip, n in counts.items():
            self.logger.info("host %s has %d connections", ip, n)
            if n > LIMIT and ip not in self.blocklist:
                self.blocklist.append(ip)
                drop_match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
                self.send_rule(100, drop_match, [])          # DROP rule for the IP address
                mac = self.mac_of.get(ip)
                if mac:                                      # also drop the device itself (its MAC),
                    self.send_rule(100, parser.OFPMatch(eth_src=mac), [])   # so a new IP does not help
                self.logger.warning("BLOCKED %s mac=%s (%d connections)", ip, mac, n)
