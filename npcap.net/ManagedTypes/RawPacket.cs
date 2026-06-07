using PacketDotNet;
using System;
using System.Collections.Generic;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace npcap.net.ManagedTypes
{
    public class RawPacket
    {
        public byte[] Data { get; init; }
        public uint Length { get; init; }
        public uint CaptureLenght { get; init; }
        public DateTime Timestamp { get; init; }
        public Packet Packet { get; init; }

        public RawPacket(LinkLayers linkLayers, IntPtr data, uint length, uint captureLength, DateTime timestamp)
        {
            Length = length;
            CaptureLenght = captureLength;
            Timestamp = timestamp;
            Data = new byte[captureLength];
            Marshal.Copy(data, Data, 0, (int)captureLength);
            Packet = Packet.ParsePacket(linkLayers, Data);
        }
    }
}
