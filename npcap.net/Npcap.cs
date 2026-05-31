using npcap.net.Exceptions;
using npcap.net.ManagedTypes;
using npcap.net.Native;
using npcap.net.Native.Libraries;
using npcap.net.Types;
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using static npcap.net.Native.WpcapStructs;

namespace npcap.net
{
    // https://npcap.com/guide/npcap-tutorial.html
    // https://npcap.com/guide/npcap-internals.html

    internal class Npcap
    {
        public bool IsReady { get; private set; }

        private readonly string _npcapDirectoryPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Npcap");
        private readonly string _npcapPacketDllName = "Packet.dll";
        private readonly string _npcapCoreDllName = "wpcap.dll";

        public Library PacketLibrary { get; init; }
        public Library CoreLibrary { get; init; }

        public Npcap()
        {
            string packetDllPath = Path.Combine(_npcapDirectoryPath, _npcapPacketDllName);
            string coreDllPath = Path.Combine(_npcapDirectoryPath, _npcapCoreDllName);

            var packetDllAddress = Bridge.LoadLibrary(packetDllPath);
            var coreDllAddress = Bridge.LoadLibrary(coreDllPath);

            if (packetDllAddress == IntPtr.Zero)
            {
                throw new DllLoadingFailedException($"Failed to load {packetDllPath}");
            }

            if (coreDllAddress == IntPtr.Zero)
            {
                throw new DllLoadingFailedException($"Failed to load {coreDllPath}");
            }

            PacketLibrary = new Library()
            {
                Name = _npcapPacketDllName,
                Path = packetDllPath,
                Handle = packetDllAddress
            };

            CoreLibrary = new Library()
            {
                Name = _npcapCoreDllName,
                Path = coreDllPath,
                Handle = coreDllAddress
            };

            IsReady = true;
        }

        public (bool Success, string? ErrorMessage) Test()
        {
            // https://npcap.com/guide/wpcap/pcap_findalldevs.html

            // https://learn.microsoft.com/en-us/dotnet/framework/interop/marshalling-strings

            StringBuilder sb = new StringBuilder(256);
            var ret = Wpcap.pcap_findalldevs_ex(Wpcap.PCAP_SRC_IF_STRING, IntPtr.Zero, out IntPtr devices, sb);
            Console.WriteLine($"{DateTime.Now} npcap.net: pcap_findalldevs_ex");
            if (ret == -1)
            {
                return (false, sb.ToString());
            }

            var deviceList = devices.ConvertIntPtrLinkedListToManagedList<pcap_if>();
            if (deviceList.Any())
            {
                PrintDevices(deviceList);
            }

            return (false, null);

            /*
             if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
    NULL 
    &alldevs, errbuf) == -1)
  {
                fprintf(stderr,
                  "Error in pcap_findalldevs_ex: %s\n",
                  errbuf);
                exit(1);
            }
            */
        }

        public unsafe void PrintDevices(List<pcap_if> devices)
        {
            // https://npcap.com/guide/npcap-tutorial.html#npcap-tutorial-devdetails
            // "Obtaining advanced information about installed devices"

            foreach (var dev in devices)
            {
                Console.WriteLine();

                bool isLoopback = (dev.flags & WpcapDefs.PCAP_IF_LOOPBACK) == WpcapDefs.PCAP_IF_LOOPBACK;

                Console.WriteLine($"\tDescription: {dev.description}");
                Console.WriteLine($"\tLoopback: {isLoopback}");
                if (dev.addresses == null) continue;
                Console.WriteLine($"\tAddress Family: {dev.addresses->addr->sa_family}");
                switch (dev.addresses->addr->sa_family)
                {
                    case AddressFamily.InterNetwork:
                        if (dev.addresses->addr != null)
                        {
                            Console.WriteLine($"\tAddress: {new IPAddress(((Ws2_32.sockaddr_in*)dev.addresses->addr)->sin_addr.s_addr)}");
                        }

                        if (dev.addresses->netmask != null)
                        {
                            Console.WriteLine($"\tNetmask: {new IPAddress(((Ws2_32.sockaddr_in*)dev.addresses->netmask)->sin_addr.s_addr)}");
                        }

                        if (dev.addresses->broadaddr != null)
                        {
                            Console.WriteLine($"\tBroadcast Address: {new IPAddress(((Ws2_32.sockaddr_in*)dev.addresses->broadaddr)->sin_addr.s_addr)}");
                        }

                        if (dev.addresses->dstaddr != null)
                        {
                            Console.WriteLine($"\tDestination Address: {new IPAddress(((Ws2_32.sockaddr_in*)dev.addresses->dstaddr)->sin_addr.s_addr)}");
                        }
                        break;
                    default:
                        Console.WriteLine("\tUnknown handling");
                        break;

                }
            }
        }
    }
}
