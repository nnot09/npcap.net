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
using System.Reflection.Metadata;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static npcap.net.Native.WpcapStructs;

namespace npcap.net
{
    public enum MinimumLoggingLevel
    {
        /// <summary>
        /// No logs.
        /// </summary>
        None,

        /// <summary>
        /// Debug logs and above (Warning, Error).
        /// </summary>
        Debug,

        /// <summary>
        /// Warning logs and above (Error).
        /// </summary>
        Warning,

        /// <summary>
        /// Only error logs.
        /// </summary>
        Error,

        /// <summary>
        /// All logs.
        /// </summary>
        Full
    }

    // https://npcap.com/guide/npcap-tutorial.html
    // https://npcap.com/guide/npcap-internals.html

    public class Npcap : IDisposable
    {
        public bool IsReady { get; private set; }

        private readonly List<IntPtr> _requestedDeviceList = new();
        private readonly string _npcapDirectoryPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Npcap");
        private readonly string _npcapPacketDllName = "Packet.dll";
        private readonly string _npcapCoreDllName = "wpcap.dll";

        public Library PacketLibrary { get; init; }
        public Library CoreLibrary { get; init; }

        public Npcap(MinimumLoggingLevel minimumLoggingLevel = MinimumLoggingLevel.Debug)
        {
            Global.InitializeLoggingLevels(minimumLoggingLevel);

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

        public void Dispose()
        {
            if (!IsReady) return;

            foreach (var devicePtrs in _requestedDeviceList)
            {
                Wpcap.pcap_freealldevs(devicePtrs);
            }

            if (CoreLibrary != null)
            {
                Bridge.FreeLibrary(CoreLibrary.Handle);
            }

            if (PacketLibrary != null)
            {
                Bridge.FreeLibrary(PacketLibrary.Handle);
            }

            IsReady = false;
        }

        public List<Device> GetDevices(Predicate<string>? descriptionFilter)
        {
            if (!IsReady) return new List<Device>();

            ConsoleEx.Debug("getting devices (local)");

            StringBuilder errBuffer = new StringBuilder(WpcapDefs.General.PCAP_ERRBUF_SIZE);
            var result = Wpcap.pcap_findalldevs(out IntPtr devicesPtr, errBuffer);
            if (result == WpcapDefs.ErrorCodes.PCAP_ERROR)
            {
                ConsoleEx.Error($"failed to find devices: {errBuffer}");
                return new List<Device>();
            }

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

        public event EventHandler<PacketEx> PacketCaptured;
        public void OnPacketCaptured(PacketEx packet)
        {
            PacketCaptured?.Invoke(this, packet);
        }

        public (bool Success, Task Task, CancellationTokenSource CancellationTokenSource) Capture(Device device, string filter)
        {
            CancellationTokenSource cts = new CancellationTokenSource();
            var defaultReturn = (false, Task.CompletedTask, cts);

            unsafe
            {
                ConsoleEx.Debug($"compiling capture filter '{filter}'...");

                bpf_program* bpfFilter = (bpf_program*)NativeMemory.Alloc((nuint)Marshal.SizeOf<bpf_program>());
                // fixed (byte* bpfFilter = new byte[sizeof(bpf_program)])

                var result = Wpcap.pcap_compile(device.Handle, bpfFilter, filter, 1, (UInt32)device.Netmask.ToLongIpAddress());
                if (result < 0)
                {
                    string pcapError = Wpcap.pcap_geterr(device.Handle);
                    ConsoleEx.Error($"failed to compile filter '{filter}' of '{device.Name}': {pcapError}");
                    Wpcap.pcap_freecode(bpfFilter);
                    cts.Dispose();
                    return defaultReturn;
                }

                ConsoleEx.Debug($"setting capture filter '{filter}'...");

                // Apply the compiled filter
                // if (Wpcap.pcap_setfilter((WpcapStructs.pcap*)handle, &bpfFilter) < 0)
                if (Wpcap.pcap_setfilter((WpcapStructs.pcap*)device.Handle, bpfFilter) < 0)
                {
                    string pcapError = Wpcap.pcap_geterr(device.Handle);
                    ConsoleEx.Error($"failed to set filter '{filter}' of '{device.Name}': {pcapError}");
                    Wpcap.pcap_freecode(bpfFilter);
                    cts.Dispose();
                    return defaultReturn;
                }

                ConsoleEx.Debug($"starting packet capture of device '{device.Name}' using '{filter}' filter...");

                var t = Task.Run(async () =>
                {
                    try
                    {
                        result = -1;
                        while ((result = Wpcap.pcap_next_ex((WpcapStructs.pcap*)device.Handle, out IntPtr packetHeader, out IntPtr data)) >= 0)
                        {
                            if (cts.IsCancellationRequested)
                            {
                                break;
                            }

                            if (result == 0)
                            {
                                ConsoleEx.Warning("timeout/no data");
                                continue;
                            }

                            if (packetHeader == IntPtr.Zero || data == IntPtr.Zero)
                            {
                                ConsoleEx.Warning($"received nullptr from packet header or data");
                                continue;
                            }

                            var hdr = Marshal.PtrToStructure<pcap_pkthdr>(packetHeader);
                            OnPacketCaptured(new PacketEx(data, hdr.len, hdr.caplen, DateTime.Now));
                        }
                    }
                    finally
                    {
                        cts.Dispose();
                        Wpcap.pcap_freecode(bpfFilter);
                    }
                }, cancellationToken: cts.Token);

                ConsoleEx.Debug($"capture task for device '{device.Name}' started");

                return (true, t, cts);
            }
        }

        public (bool Success, string? ErrorMessage) Test()
        {
            return default;

            // https://npcap.com/guide/wpcap/pcap_findalldevs.html

            // https://learn.microsoft.com/en-us/dotnet/framework/interop/marshalling-strings

            //StringBuilder sb = new StringBuilder(256);
            //var ret = Wpcap.pcap_findalldevs_ex(Wpcap.PCAP_SRC_IF_STRING, IntPtr.Zero, out IntPtr devices, sb);
            //Console.WriteLine($"{DateTime.Now} npcap.net: pcap_findalldevs_ex");
            //if (ret == -1)
            //{
            //    return (false, sb.ToString());
            //}

            //var deviceList = devices.ConvertIntPtrLinkedListToManagedList<pcap_if>();
            //if (deviceList.Any())
            //{
            //    PrintDevices(deviceList);
            //}

            //OpenDevices(deviceList, devices);

            //return (false, null);

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
    }
}
