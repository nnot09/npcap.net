using System;
using System.Collections.Generic;
using System.Runtime.Intrinsics.Arm;
using System.Text;

namespace npcap.net.ManagedTypes
{
    // https://npcap.com/guide/wpcap/pcap-filter.html

    internal interface IFilter
    {
        // TODO
    }

    internal class CaptureFilter
    {
        // fddi = alias for ether
        // tr and wlan = alias for ether

        // TODO
        private readonly string[] _type = { "host", "net", "port", "portrange" };
        private readonly string[] _dir = { "src", "dst", "src or dst", "src and dst", "ra", "ta", "addr1", "addr2", "addr3", "addr4" };
        private readonly string[] _proto = { "ether", "fddi", "tr", "wlan", "ip", "ip6", "arp", "rarp", "decnet", "sctp", "tcp", "udp" };
        private readonly string[] _otherPrimitives = { "less", "greater", "gateway", "broadcast" };
        private readonly string[] _conditionalExpressions = { "and", "or", "not" };
        private readonly string[] _conditionalOperators = { "&&", "||", "!" }; 

        //public void ParseFilterString(string filter)
        //{
        //    for (int i = 0; i < filter.Length; i++)
        //    {
        //        char current = filter[i];
        //    }
        //}
    }
}
