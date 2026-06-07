using npcap.net.ManagedTypes;
using npcap.net.Native;

namespace npcap.net.Tests
{
    [TestClass]
    public class DeviceTests
    {
        private static Device CreateDevice(WpcapDefs.InterfaceFlags flags, string name = "eth0", string description = "Test Device")
            => new Device(name, description, flags);

        [TestMethod]
        public void Device_IsLoopback_TrueWhenFlagSet()
        {
            var device = CreateDevice(WpcapDefs.InterfaceFlags.PCAP_IF_LOOPBACK);
            Assert.IsTrue(device.IsLoopback);
        }

        [TestMethod]
        public void Device_IsLoopback_FalseWhenFlagNotSet()
        {
            var device = CreateDevice(WpcapDefs.InterfaceFlags.PCAP_IF_UP);
            Assert.IsFalse(device.IsLoopback);
        }

        [TestMethod]
        public void Device_IsUp_TrueWhenFlagSet()
        {
            var device = CreateDevice(WpcapDefs.InterfaceFlags.PCAP_IF_UP);
            Assert.IsTrue(device.IsUp);
        }

        [TestMethod]
        public void Device_IsRunning_TrueWhenFlagSet()
        {
            var device = CreateDevice(WpcapDefs.InterfaceFlags.PCAP_IF_RUNNING);
            Assert.IsTrue(device.IsRunning);
        }

        [TestMethod]
        public void Device_IsWireless_TrueWhenFlagSet()
        {
            var device = CreateDevice(WpcapDefs.InterfaceFlags.PCAP_IF_WIRELESS);
            Assert.IsTrue(device.IsWireless);
        }

        [TestMethod]
        public void Device_IsConnected_TrueWhenFlagSet()
        {
            var device = CreateDevice(WpcapDefs.InterfaceFlags.PCAP_IF_CONNECTION_STATUS_CONNECTED);
            Assert.IsTrue(device.IsConnected);
        }

        [TestMethod]
        public void Device_IsDisconnected_TrueWhenFlagSet()
        {
            var device = CreateDevice(WpcapDefs.InterfaceFlags.PCAP_IF_CONNECTION_STATUS_DISCONNECTED);
            Assert.IsTrue(device.IsDisconnected);
        }

        [TestMethod]
        public void Device_IsNotApplicable_TrueWhenFlagSet()
        {
            var device = CreateDevice(WpcapDefs.InterfaceFlags.PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE);
            Assert.IsTrue(device.IsNotApplicable);
        }

        [TestMethod]
        public void Device_MultipleFlags_AllReported()
        {
            var flags = WpcapDefs.InterfaceFlags.PCAP_IF_UP
                      | WpcapDefs.InterfaceFlags.PCAP_IF_RUNNING
                      | WpcapDefs.InterfaceFlags.PCAP_IF_WIRELESS;

            var device = CreateDevice(flags);

            Assert.IsTrue(device.IsUp);
            Assert.IsTrue(device.IsRunning);
            Assert.IsTrue(device.IsWireless);
            Assert.IsFalse(device.IsLoopback);
        }

        [TestMethod]
        public void Device_NoFlags_AllFalse()
        {
            var device = CreateDevice((WpcapDefs.InterfaceFlags)0);

            Assert.IsFalse(device.IsLoopback);
            Assert.IsFalse(device.IsUp);
            Assert.IsFalse(device.IsRunning);
            Assert.IsFalse(device.IsWireless);
            Assert.IsFalse(device.IsConnected);
            Assert.IsFalse(device.IsDisconnected);
        }

        [TestMethod]
        public void Device_Handle_DefaultIsZero()
        {
            var device = CreateDevice(WpcapDefs.InterfaceFlags.PCAP_IF_UP);
            Assert.AreEqual(IntPtr.Zero, device.Handle);
        }

        [TestMethod]
        public void Device_NameAndDescription_StoredCorrectly()
        {
            var device = new Device("\\Device\\NPF_{ABC}", "Intel Ethernet", WpcapDefs.InterfaceFlags.PCAP_IF_UP);

            Assert.AreEqual("\\Device\\NPF_{ABC}", device.Name);
            Assert.AreEqual("Intel Ethernet", device.Description);
        }
    }
}
