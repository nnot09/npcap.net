using npcap.net.Native;
using npcap.net.NewFolder;
using npcap.net.Types;
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Runtime.InteropServices;
using System.Text;

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
            if (ret == 0)
            {
                return (false, sb.ToString());
            }

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

            return (true, null);
        }
    }
}
