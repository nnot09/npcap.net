using npcap.net.ManagedTypes;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices.Marshalling;
using System.Text;

namespace npcap.net.Bridge
{
    public class EventsControl
    {
        public delegate void PacketCapturedHandler(Packet capturedPacket);
        public delegate void TimeoutHandler(Device device);
        public delegate void OnDeviceErrorHandler(Device device, string? errorMessage);

        public event PacketCapturedHandler? PacketCaptured;
        public event TimeoutHandler? Timeout;
        public event OnDeviceErrorHandler? DeviceError;
        
        private readonly Npcap _npcap;

        public EventsControl(Npcap npcap)
        {
            this._npcap = npcap;
        }

        internal void OnPacketCaptured(Packet packet)
        {
            PacketCaptured?.Invoke(packet);
        }

        internal void OnTimeout(Device device)
        {
            Timeout?.Invoke(device);
        }

        internal void OnDeviceError(Device device, string? errorMessage)
        {
            DeviceError?.Invoke(device, errorMessage);
        }
    }
}
