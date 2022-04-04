# TVWS_main_filters - Munthir Chater

# Values for field, display, and flow filters that are hardcoded to check user input and ensure validity/compatibility
displayFilters = ["tcp", "udp"]

countFilters = ["frame.time_epoch", "frame.time_delta", "frame.len", "ip.src", "ip.dst", "eth.src", "eth.dst",
                "tcp.len", "ip.proto", "ip.ttl", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
                "tcp.flags", "tcp.flags.ack", "tcp.flags.syn", "tcp.flags.fin", "tcp.analysis.ack_rtt", "cpkt",
                "tcp.analysis.retransmission", "tcp.time_delta", "udp.time_delta", "tcp.analysis.bytes_in_flight",
                "tcp.window_size", "http.request", "http.request.uri", "http.request.full_uri", "http.host",
                "http.request.uri.path", "http.request.uri.query", "http.response.code", "icmp.type", "flw_tcpflows",
                "successfulTCPFlows", "failedTCPFlows", "pkt_tcpflows", "uppkt_tcpflows", "dwpkt_tcpflows",
                "services_tcpflows", "servicespackets_tcpflows", "site_tcpflows", "siteSuccess_tcpflows",
                "siteFail_tcpflows", "sitePackets_tcpflows", "siteSuccessPackets_tcpflows", "siteFailPackets_tcpflows",
                "flw_udpflows", "pkt_udpflows", "uppkt_udpflows", "dwpkt_udpflows", "services_udpflows",
                "servicespackets_udpflows", "site_udpflows", "sitePackets_udpflows"]
totalFilters = ["frame.time_epoch", "frame.time_delta", "frame.len", "tcp.len", "ip.ttl", "tcp.analysis.ack_rtt",
                "tcp.time_delta", "udp.time_delta", "tcp.analysis.bytes_in_flight", "tcp.window_size",
                "pkt_tcpflows", "uppkt_tcpflows", "dwpkt_tcpflows", "flwsiz_tcpflows", "upflwsiz_tcpflows",
                "dwflwsiz_tcpflows", "flwsiz_successfulTCPFlows", "flwsiz_failedTCPFlows", "pktsiz_tcpflows",
                "uppktsiz_tcpflows", "dwpktsiz_tcpflows", "sitePackets_tcpflows", "siteSuccessPackets_tcpflows",
                "siteFailPackets_tcpflows", "siteBytes_tcpflows", "siteSuccessBytes_tcpflows", "siteFailBytes_tcpflows",
                "pkt_udpflows", "uppkt_udpflows", "dwpkt_udpflows", "flwsiz_udpflows", "upflwsiz_udpflows",
                "dwflwsiz_udpflows", "pktsiz_udpflows", "uppktsiz_udpflows", "dwpktsiz_udpflows", "sitePackets_udpflows",
                "siteBytes_udpflows"]
averageFilters = ["frame.time_epoch", "frame.time_delta", "frame.len", "tcp.len", "ip.ttl", "tcp.analysis.ack_rtt",
                  "tcp.time_delta", "udp.time_delta", "tcp.analysis.bytes_in_flight", "tcp.window_size",
                  "pkt_tcpflows", "uppkt_tcpflows", "dwpkt_tcpflows", "flwsiz_tcpflows", "upflwsiz_tcpflows",
                  "dwflwsiz_tcpflows", "flwsiz_successfulTCPFlows", "flwsiz_failedTCPFlows", "pktsiz_tcpflows",
                  "uppktsiz_tcpflows", "dwpktsiz_tcpflows", "sitePackets_tcpflows", "siteSuccessPackets_tcpflows",
                  "siteFailPackets_tcpflows", "siteBytes_tcpflows", "siteSuccessBytes_tcpflows", "siteFailBytes_tcpflows",
                  "pkt_udpflows", "uppkt_udpflows", "dwpkt_udpflows", "flwsiz_udpflows", "upflwsiz_udpflows",
                  "dwflwsiz_udpflows", "pktsiz_udpflows", "uppktsiz_udpflows", "dwpktsiz_udpflows", "sitePackets_udpflows",
                  "siteBytes_udpflows"]

fieldFilters = ["frame.time_epoch", "frame.time_delta", "frame.len", "ip.src", "ip.dst", "eth.src", "eth.dst", "tcp.len",
                "ip.proto", "ip.ttl", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.flags",
                "tcp.flags.ack", "tcp.flags.syn", "tcp.flags.fin", "tcp.analysis.ack_rtt", "tcp.analysis.retransmission",
                "tcp.time_delta", "udp.time_delta", "tcp.analysis.bytes_in_flight", "tcp.window_size",
                "http.request", "http.request.uri", "http.request.full_uri", "http.host", "http.request.uri.path",
                "http.request.uri.query", "http.response.code", "icmp.type"]
tcpflowFilters = ["flw_tcpflows", "successfulTCPFlows", "failedTCPFlows", "pkt_tcpflows", "uppkt_tcpflows",
                  "dwpkt_tcpflows", "flwsiz_tcpflows", "upflwsiz_tcpflows", "dwflwsiz_tcpflows", "flwsiz_successfulTCPFlows",
                  "flwsiz_failedTCPFlows", "pktsiz_tcpflows", "uppktsiz_tcpflows", "dwpktsiz_tcpflows", "services_tcpflows",
                  "servicespackets_tcpflows", "site_tcpflows", "siteSuccess_tcpflows", "siteFail_tcpflows", "sitePackets_tcpflows",
                  "siteSuccessPackets_tcpflows", "siteFailPackets_tcpflows", "siteBytes_tcpflows",
                  "siteSuccessBytes_tcpflows", "siteFailBytes_tcpflows"]
udpflowFilters = ["flw_udpflows", "pkt_udpflows", "uppkt_udpflows", "dwpkt_udpflows", "flwsiz_udpflows", "upflwsiz_udpflows",
                  "dwflwsiz_udpflows", "pktsiz_udpflows", "uppktsiz_udpflows", "dwpktsiz_udpflows", "services_udpflows",
                  "servicespackets_udpflows", "site_udpflows", "sitePackets_udpflows", "siteBytes_udpflows"]

siteFilters = ["site_tcpflows", "siteSuccess_tcpflows", "siteFail_tcpflows", "sitePackets_tcpflows",
               "siteSuccessPackets_tcpflows", "siteFailPackets_tcpflows", "site_udpflows", "sitePackets_udpflows"]