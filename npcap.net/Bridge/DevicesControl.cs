using npcap.net.ManagedTypes;
using npcap.net.Native;
using System;
using System.Collections.Generic;
using System.Text;
using static npcap.net.Native.WpcapStructs;

namespace npcap.net.Bridge
{
    public class DevicesControl
    {
        private readonly Npcap _npcap;

        public DevicesControl(Npcap npcap)
        {
            this._npcap = npcap;
        }

        public List<Device> GetDevices(Predicate<string>? descriptionFilter)
        {
            if (!_npcap.IsReady) return new List<Device>();

            ConsoleEx.Debug("getting devices (local)");

            StringBuilder errBuffer = new StringBuilder(WpcapDefs.General.PCAP_ERRBUF_SIZE);
            var result = Wpcap.pcap_findalldevs(out IntPtr devicesPtr, errBuffer);
            if (result == WpcapDefs.ErrorCodes.PCAP_ERROR)
            {
                ConsoleEx.Error($"failed to find devices: {errBuffer}");
                return new List<Device>();
            }

            _npcap.AddRequestedDevice(devicesPtr);

            var devices = devicesPtr.ConvertIntPtrLinkedListToManagedList<pcap_if>().Select(p => new Device(p));
            if (!ReferenceEquals(descriptionFilter, null))
            {
                ConsoleEx.Debug("applying description filter");
                devices = devices.Where(d => descriptionFilter(d.Description));
            }

            return devices.ToList();
        }

        public List<Device> GetDevices() => GetDevices(descriptionFilter: null);

        public Device? OpenDevice(
            Device device,
            WpcapDefs.PcapOpenOptions options,
            int captureSnapLength = ushort.MaxValue,
            int timeout = 1000,
            IntPtr remoteAuth = default)
        {
            if (!_npcap.IsReady) return null;

            if (ReferenceEquals(device, null))
            {
                ConsoleEx.Error("device is null");
                return device;
            }

            ConsoleEx.Debug($"opening device '{device.Name}'...");

            StringBuilder errBuffer = new StringBuilder(WpcapDefs.General.PCAP_ERRBUF_SIZE);
            IntPtr handle = Wpcap.pcap_open(device.Name, captureSnapLength, (int)options, timeout, remoteAuth, errBuffer);
            if (handle == IntPtr.Zero)
            {
                ConsoleEx.Error($"failed to open device '{device.Name}': {errBuffer}");
                return device;
            }

            ConsoleEx.Debug($"device '{device.Name}' opened successfully: 0x{handle.ToString("x")}");
            device.Handle = handle;
            return device;
        }
    }
}
