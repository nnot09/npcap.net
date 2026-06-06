using System;
using System.Collections.Generic;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace npcap.net.ManagedTypes
{
    public class Packet
    {
        public byte[] Data { get; init; }
        public uint Length { get; init; }
        public uint CaptureLenght { get; init; }
        public DateTime Timestamp { get; init; }

        public Packet(IntPtr data, uint length, uint captureLength, DateTime timestamp)
        {
            Length = length;
            CaptureLenght = captureLength;
            Timestamp = timestamp;
            Data = new byte[captureLength];
            Marshal.Copy(data, Data, 0, (int)captureLength);
        }

        public override string ToString()
        {
            return $"{string.Join(" ", Data.Select(p => p.ToString("x2")))}";
        }
    }

    public class PacketEx : Packet
    {
        public string Contents { get; init; }
        public string ContentsHex { get; init; }

        public PacketEx(IntPtr data, uint length, uint captureLength, DateTime timestamp) : base(data, length, captureLength, timestamp)
        {
            var horrific = Data.Select(p => (char)p)
                               .Select(p => char.IsAscii(p) ? p : '.')
                               .ToArray();

            var horrific2 = Data.Select(p => p.ToString("x"));

            Contents = string.Concat(horrific);
            ContentsHex = string.Join(" ", horrific2);
        }
    }
}
