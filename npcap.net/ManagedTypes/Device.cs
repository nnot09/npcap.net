using npcap.net.Native;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace npcap.net.ManagedTypes
{
    [DebuggerDisplay("Name = {Name}, Description = {Description}, Address = {Address}")]
    internal class Device
    {
        public string Name { get; init; }
        public string Description { get; init; }
        public string Address { get; init; }

        public Device(string name, string description, string address)
        {
            Name = name;
            Description = description;
            Address = address;
        }

        public Device(WpcapStructs.pcap_if pcap) : this(pcap.name, pcap.description, "test") { }
    }
}
