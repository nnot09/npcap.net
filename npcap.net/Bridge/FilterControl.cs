using npcap.net.ManagedTypes;
using npcap.net.Native;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using static npcap.net.Native.WpcapStructs;
using static System.Net.WebRequestMethods;

namespace npcap.net.Bridge
{
    public class FilterControl
    {
        private readonly Npcap _npcap;

        public FilterControl(Npcap npcap)
        {
            _npcap = npcap;
        }

        public string Create(string filter) => filter; // hidden magic!
        public unsafe bpf_program* Compile(Device device, string filter) // TODO tbd with .NET style fitler
        {
            ConsoleEx.Debug($"compiling capture filter '{filter}' for device '{device.Name}'...");

            bpf_program* bpfFilter = (bpf_program*)NativeMemory.Alloc((nuint)Marshal.SizeOf<bpf_program>()); // seriously consider using stackalloc?

            var result = Wpcap.pcap_compile(device.Handle, bpfFilter, filter, 1, (UInt32)device.Netmask.ToLongIpAddress());
            if (result < 0)
            {
                string pcapError = Wpcap.pcap_geterr(device.Handle);
                ConsoleEx.Error($"failed to compile filter '{filter}' of '{device.Name}': {pcapError}");
                Wpcap.pcap_freecode(bpfFilter);
                return null;
            }

            return bpfFilter;
        }

        public unsafe bool SetFilter(Device device, bpf_program* bpfFilter) // TODO tbd with .NET style fitler
        {
            ConsoleEx.Debug($"setting capture filter for device '{device.Name}'...");

            var result = Wpcap.pcap_setfilter((WpcapStructs.pcap*)device.Handle, bpfFilter);
            if (result < 0)
            {
                string pcapError = Wpcap.pcap_geterr(device.Handle);
                ConsoleEx.Error($"failed to set filter of '{device.Name}': {pcapError}");
                Wpcap.pcap_freecode(bpfFilter);
                return false;
            }

            return true;
        }
    }
}
