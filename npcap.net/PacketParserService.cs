using npcap.net.ManagedTypes;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using static npcap.net.W32PacketStructs;

namespace npcap.net
{
    // https://npcap.com/guide/npcap-tutorial.html#npcap-tutorial-devdetails
    internal unsafe class W32PacketStructs
    {
        public struct ip_address
        {
            public byte byte1;
            public byte byte2;
            public byte byte3;
            public byte byte4;
        }

        /* IPv4 header */
        public struct ip_header
        {
            public byte ver_ihl; // Version (4 bits) + IP header length (4 bits)
            public byte tos;     // Type of service 
            public ushort tlen;    // Total length 
            public ushort identification; // Identification
            public ushort flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
            public byte ttl;      // Time to live
            public byte proto;    // Protocol
            public ushort crc;      // Header checksum
            public ip_address saddr; // Source address
            public ip_address daddr; // Destination address
            public uint op_pad;     // Option + Padding
        }

        /* UDP header */
        public struct udp_header
        {
            public ushort sport; // Source port
            public ushort dport; // Destination port
            public ushort len;   // Datagram length
            public ushort crc;   // Checksum
        }
    }


    public record TranslatedPacket(IPAddress Source, IPAddress Destination, byte[] RawData);

    //internal class TranslatedPacket
    //{
    //    public IPAddress Source { get; set; }
    //    public IPAddress Destination { get; set; }
    //    public byte[] RawData { get; set; }
    //}

    internal static class PacketParserService
    {
        public static TranslatedPacket ParsePacket(Packet packet)
        {
            unsafe
            {
                /*
                   ih = (ip_header *) (pkt_data + 14); //length of ethernet header
                                                    
                   // retireve the position of the udp header
                   ip_len = (ih->ver_ihl & 0xf) * 4;
                   uh = (udp_header*)((u_char*)ih + ip_len);
                */

                int iplen = 0;
                fixed (byte* ptr = packet.Data)
                {
                    ip_header* iph = (ip_header*)(ptr + 14);
                    //iplen = (iph->ver_ihl & 0xf) * 4;
                    //udp_header* uph = (udp_header*)(iph + iplen);

                    byte[] source = { iph->saddr.byte1, iph->saddr.byte2, iph->saddr.byte3, iph->saddr.byte4 };
                    byte[] destination = { iph->daddr.byte1, iph->daddr.byte2, iph->daddr.byte3, iph->daddr.byte4 };

                    return new TranslatedPacket(new IPAddress(source), new IPAddress(destination), packet.Data);
                }
            }
        }
    }
}
