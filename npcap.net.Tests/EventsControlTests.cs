using npcap.net.Bridge;
using npcap.net.ManagedTypes;
using npcap.net.Native;

namespace npcap.net.Tests
{
    [TestClass]
    public class EventsControlTests
    {
        // EventsControl requires an Npcap instance for its constructor, but only stores
        // it as a field and never uses it in the event-dispatch methods, so we can pass
        // null safely here without triggering any native calls.
        private static EventsControl CreateEventsControl()
        {
            return (EventsControl)Activator.CreateInstance(
                typeof(EventsControl),
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Public,
                null,
                [null!],
                null)!;
        }

        private static Device MakeDevice()
            => new Device("eth0", "Test", WpcapDefs.InterfaceFlags.PCAP_IF_UP);

        [TestMethod]
        public void PacketCaptured_FiresWhenSubscribed()
        {
            var events = CreateEventsControl();
            RawPacket? received = null;
            events.PacketCaptured += p => received = p;

            var packet = MakeRawPacket();
            events.OnPacketCaptured(packet);

            Assert.AreSame(packet, received);
        }

        [TestMethod]
        public void PacketCaptured_DoesNotThrow_WhenNoSubscribers()
        {
            var events = CreateEventsControl();
            // Should not throw
            events.OnPacketCaptured(MakeRawPacket());
        }

        [TestMethod]
        public void Timeout_FiresWhenSubscribed()
        {
            var events = CreateEventsControl();
            Device? received = null;
            events.Timeout += d => received = d;

            var device = MakeDevice();
            events.OnTimeout(device);

            Assert.AreSame(device, received);
        }

        [TestMethod]
        public void Timeout_DoesNotThrow_WhenNoSubscribers()
        {
            var events = CreateEventsControl();
            events.OnTimeout(MakeDevice());
        }

        [TestMethod]
        public void DeviceError_FiresWhenSubscribed()
        {
            var events = CreateEventsControl();
            Device? receivedDevice = null;
            string? receivedMessage = null;

            events.DeviceError += (d, m) => { receivedDevice = d; receivedMessage = m; };

            var device = MakeDevice();
            events.OnDeviceError(device, "test error");

            Assert.AreSame(device, receivedDevice);
            Assert.AreEqual("test error", receivedMessage);
        }

        [TestMethod]
        public void DeviceError_NullMessage_PassedThrough()
        {
            var events = CreateEventsControl();
            string? receivedMessage = "initial";
            events.DeviceError += (_, m) => receivedMessage = m;

            events.OnDeviceError(MakeDevice(), null);

            Assert.IsNull(receivedMessage);
        }

        [TestMethod]
        public void PacketCaptured_MultipleSubscribers_AllInvoked()
        {
            var events = CreateEventsControl();
            int callCount = 0;
            events.PacketCaptured += _ => callCount++;
            events.PacketCaptured += _ => callCount++;

            events.OnPacketCaptured(MakeRawPacket());

            Assert.AreEqual(2, callCount);
        }

        // Creates a minimal valid RawPacket using a small Ethernet frame in pinned memory.
        private static unsafe RawPacket MakeRawPacket()
        {
            byte[] frame =
            [
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                0x08, 0x00,
                0x45, 0x00, 0x00, 0x14,
                0x00, 0x01, 0x40, 0x00,
                0x40, 0x11, 0x00, 0x00,
                0xC0, 0xA8, 0x01, 0x01,
                0xC0, 0xA8, 0x01, 0x02,
            ];
            fixed (byte* ptr = frame)
            {
                return new RawPacket(PacketDotNet.LinkLayers.Ethernet, (IntPtr)ptr, (uint)frame.Length, (uint)frame.Length, DateTime.UtcNow);
            }
        }
    }
}
