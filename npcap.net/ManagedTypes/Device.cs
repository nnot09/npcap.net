using npcap.net.Native;
using npcap.net.Native.Libraries;
using PacketDotNet;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using static npcap.net.Native.WpcapDefs;

namespace npcap.net.ManagedTypes
{
    [DebuggerDisplay("Name = {Name}, Description = {Description}, Flags = {Flags}")]
    public class Device : IDisposable
    {
        public string Name { get; init; }
        public string Description { get; init; }
        public InterfaceFlags Flags { get; init; }
        public AddressFamily AddressFamily { get; init; }
        public IPAddress Address { get; init; }
        public IPAddress Netmask { get; init; }
        public IPAddress BroadcastAddress { get; init; }
        public IPAddress DestinationAddress { get; init; }
        public IntPtr Handle { get; set; }

        public bool IsLoopback => Flags.HasFlag(InterfaceFlags.PCAP_IF_LOOPBACK);
        public bool IsUp => Flags.HasFlag(InterfaceFlags.PCAP_IF_UP);
        public bool IsRunning => Flags.HasFlag(InterfaceFlags.PCAP_IF_RUNNING);
        public bool IsWireless => Flags.HasFlag(InterfaceFlags.PCAP_IF_WIRELESS);
        public bool IsConnected => Flags.HasFlag(InterfaceFlags.PCAP_IF_CONNECTION_STATUS_CONNECTED);
        public bool IsDisconnected => Flags.HasFlag(InterfaceFlags.PCAP_IF_CONNECTION_STATUS_DISCONNECTED);
        public bool IsNotApplicable => Flags.HasFlag(InterfaceFlags.PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE);

        public Device(string name, string description, InterfaceFlags flags)
        {
            Name = name;
            Description = description;
            Flags = flags;
        }

        public Device(WpcapStructs.pcap_if pcap) 
            : this(pcap.name, pcap.description, (InterfaceFlags)pcap.flags) 
        { 
            unsafe
            {
                AddressFamily = AddressFamily.Unknown;
                Address = IPAddress.None;
                Netmask = IPAddress.None;
                BroadcastAddress = IPAddress.None;
                DestinationAddress = IPAddress.None;

                if (pcap.addresses == null) return;
                if (pcap.addresses->addr != null)
                {
                    AddressFamily = pcap.addresses->addr->sa_family;
                }

                if (pcap.addresses->netmask != null)
                {
                    Netmask = new IPAddress(((Ws2_32.sockaddr_in*)pcap.addresses->netmask)->sin_addr.s_addr);
                }

                if (pcap.addresses->broadaddr != null)
                {
                    BroadcastAddress = new IPAddress(((Ws2_32.sockaddr_in*)pcap.addresses->broadaddr)->sin_addr.s_addr);
                }

                if (pcap.addresses->dstaddr != null)
                {
                    DestinationAddress = new IPAddress(((Ws2_32.sockaddr_in*)pcap.addresses->dstaddr)->sin_addr.s_addr);
                }
            }
        }

        public void Dispose()
        {
            if (Handle != IntPtr.Zero)
            {
                Wpcap.pcap_close(Handle);
                Handle = IntPtr.Zero;
            }
        }
    }
}
