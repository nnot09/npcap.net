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

namespace npcap.net.Bridge
{
    // https://npcap.com/guide/npcap-tutorial.html
    // https://npcap.com/guide/npcap-internals.html

    /// <summary>
    /// Core Npcap class.
    /// </summary>
    public class Npcap : IAsyncDisposable
    {
        public bool IsReady { get; private set; }
        public bool EnablePacketPrinting { get; set; }

        private readonly List<IntPtr> _requestedDeviceList = new();
        private readonly string _npcapDirectoryPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Npcap");
        private readonly string _npcapPacketDllName = "Packet.dll";
        private readonly string _npcapCoreDllName = "wpcap.dll";

        internal Library PacketLibrary { get; init; }
        internal Library CoreLibrary { get; init; }

        public EventsControl Events { get; init; }
        public FilterControl Filter { get; init; }
        public CaptureControl Capture { get; init; }
        public DevicesControl Devices { get; init; }

        public Npcap(MinimumLoggingLevel minimumLoggingLevel = MinimumLoggingLevel.Debug)
        {
            Global.InitializeLoggingLevels(minimumLoggingLevel);

            string packetDllPath = Path.Combine(_npcapDirectoryPath, _npcapPacketDllName);
            string coreDllPath = Path.Combine(_npcapDirectoryPath, _npcapCoreDllName);

            var packetDllAddress = NativeHelpers.LoadLibrary(packetDllPath);
            var coreDllAddress = NativeHelpers.LoadLibrary(coreDllPath);

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

            Events = new(this);
            Filter = new(this);
            Capture = new(this);
            Devices = new(this);

            IsReady = true;
        }

        internal void AddRequestedDevice(IntPtr devicePtr)
        {
            if (devicePtr == IntPtr.Zero)
            {
                ConsoleEx.Warning("attempted to add null pointer to requested device list, skipping");
                return;
            }
            _requestedDeviceList.Add(devicePtr);
        }

        public async ValueTask DisposeAsync()
        {
            if (!IsReady) return;

            foreach (var devicePtrs in _requestedDeviceList)
            {
                Wpcap.pcap_freealldevs(devicePtrs);
            }

            if (CoreLibrary != null)
            {
                NativeHelpers.FreeLibrary(CoreLibrary.Handle);
            }

            if (PacketLibrary != null)
            {
                NativeHelpers.FreeLibrary(PacketLibrary.Handle);
            }

            await MessageService.StopAsync();

            IsReady = false;
        }
    }
}
