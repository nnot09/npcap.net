using npcap.net.ManagedTypes;
using PacketDotNet;
using System.Runtime.InteropServices;

namespace npcap.net.Tests
{
    [TestClass]
    public class RawPacketTests
    {
        // Minimal valid Ethernet + IPv4 + TCP frame (54 bytes)
        // dst mac, src mac, ethertype 0x0800, IP header (20 bytes), TCP header (20 bytes)
        private static readonly byte[] _ethernetTcpFrame =
        [
            // Ethernet header (14 bytes)
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // dst MAC: broadcast
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // src MAC
            0x08, 0x00,                            // EtherType: IPv4
            // IPv4 header (20 bytes)
            0x45, 0x00, 0x00, 0x28,               // version/IHL, DSCP, total length = 40
            0x00, 0x01, 0x40, 0x00,               // id, flags, fragment offset
            0x40, 0x06, 0x00, 0x00,               // TTL=64, protocol=TCP(6), checksum
            0xC0, 0xA8, 0x01, 0x01,               // src IP: 192.168.1.1
            0xC0, 0xA8, 0x01, 0x02,               // dst IP: 192.168.1.2
            // TCP header (20 bytes)
            0x1F, 0x90, 0x00, 0x50,               // src port: 8080, dst port: 80
            0x00, 0x00, 0x00, 0x01,               // seq number
            0x00, 0x00, 0x00, 0x00,               // ack number
            0x50, 0x02, 0xFF, 0xFF,               // data offset, flags (SYN), window size
            0x00, 0x00, 0x00, 0x00,               // checksum, urgent pointer
        ];

        private static unsafe RawPacket CreateRawPacket(byte[] frameBytes, LinkLayers linkLayers = LinkLayers.Ethernet)
        {
            fixed (byte* ptr = frameBytes)
            {
                return new RawPacket(linkLayers, (IntPtr)ptr, (uint)frameBytes.Length, (uint)frameBytes.Length, DateTime.UtcNow);
            }
        }

        [TestMethod]
        public void RawPacket_Data_CopiedCorrectly()
        {
            var packet = CreateRawPacket(_ethernetTcpFrame);

            CollectionAssert.AreEqual(_ethernetTcpFrame, packet.Data);
        }

        [TestMethod]
        public void RawPacket_Length_SetCorrectly()
        {
            var packet = CreateRawPacket(_ethernetTcpFrame);

            Assert.AreEqual((uint)_ethernetTcpFrame.Length, packet.Length);
        }

        [TestMethod]
        public void RawPacket_CaptureLength_SetCorrectly()
        {
            var packet = CreateRawPacket(_ethernetTcpFrame);

            Assert.AreEqual((uint)_ethernetTcpFrame.Length, packet.CaptureLenght);
        }

        [TestMethod]
        public void RawPacket_Timestamp_SetCorrectly()
        {
            var before = DateTime.UtcNow;
            var packet = CreateRawPacket(_ethernetTcpFrame);
            var after = DateTime.UtcNow;

            Assert.IsTrue(packet.Timestamp >= before && packet.Timestamp <= after);
        }

        [TestMethod]
        public void RawPacket_Packet_ParsedAsEthernet()
        {
            var packet = CreateRawPacket(_ethernetTcpFrame);

            Assert.IsNotNull(packet.Packet);
            Assert.IsInstanceOfType<EthernetPacket>(packet.Packet);
        }

        [TestMethod]
        public void RawPacket_Packet_ContainsTcpPayload()
        {
            var packet = CreateRawPacket(_ethernetTcpFrame);

            var tcp = packet.Packet.Extract<TcpPacket>();
            Assert.IsNotNull(tcp);
            Assert.AreEqual(8080, tcp.SourcePort);
            Assert.AreEqual(80, tcp.DestinationPort);
        }

        [TestMethod]
        public void RawPacket_Data_IsIndependentCopy()
        {
            var original = (byte[])_ethernetTcpFrame.Clone();
            var packet = CreateRawPacket(original);

            // Mutate after construction — packet.Data must not change
            original[0] = 0x00;

            Assert.AreEqual(0xFF, packet.Data[0]);
        }
    }
}
