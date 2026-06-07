using npcap.net;
using System.Net;

namespace npcap.net.Tests
{
    [TestClass]
    public class HelpersTests
    {
        // --- IsNullOrWhiteSpace ---

        [TestMethod]
        public void IsNullOrWhiteSpace_NullString_ReturnsTrue()
        {
            string? value = null;
            Assert.IsTrue(value.IsNullOrWhiteSpace());
        }

        [TestMethod]
        public void IsNullOrWhiteSpace_EmptyString_ReturnsTrue()
        {
            Assert.IsTrue(string.Empty.IsNullOrWhiteSpace());
        }

        [TestMethod]
        public void IsNullOrWhiteSpace_WhitespaceOnly_ReturnsTrue()
        {
            Assert.IsTrue("   ".IsNullOrWhiteSpace());
        }

        [TestMethod]
        public void IsNullOrWhiteSpace_NonEmptyString_ReturnsFalse()
        {
            Assert.IsFalse("hello".IsNullOrWhiteSpace());
        }

        // --- ToLongIpAddress ---

        [TestMethod]
        public void ToLongIpAddress_IPv4_ReturnsExpectedLong()
        {
            // 192.168.1.1 bytes: [192, 168, 1, 1]
            // As little-endian int32: 0x0101A8C0 = 16820416
            var ip = IPAddress.Parse("192.168.1.1");
            var result = ip.ToLongIpAddress();

            byte[] bytes = ip.GetAddressBytes();
            long expected = BitConverter.ToInt32(bytes, 0);
            Assert.AreEqual(expected, result);
        }

        [TestMethod]
        public void ToLongIpAddress_AllZeros_ReturnsZero()
        {
            var ip = IPAddress.Parse("0.0.0.0");
            Assert.AreEqual(0L, ip.ToLongIpAddress());
        }

        [TestMethod]
        public void ToLongIpAddress_Broadcast_ReturnsExpectedLong()
        {
            var ip = IPAddress.Parse("255.255.255.255");
            byte[] bytes = ip.GetAddressBytes();
            long expected = BitConverter.ToInt32(bytes, 0);
            Assert.AreEqual(expected, ip.ToLongIpAddress());
        }

        // --- ConvertIntPtrLinkedListToManagedList ---

        [TestMethod]
        public void ConvertIntPtrLinkedListToManagedList_ZeroPtr_ReturnsEmptyList()
        {
            var result = IntPtr.Zero.ConvertIntPtrLinkedListToManagedList<DummyNode>();
            Assert.AreEqual(0, result.Count);
        }

        // Minimal ILinkedList stub for the extension-method test above.
        // A zero-terminated single node is enough; the helper stops at next == 0.
        private unsafe struct DummyNode : npcap.net.Native.WpcapStructs.ILinkedList
        {
            public DummyNode* next;
            void* npcap.net.Native.WpcapStructs.ILinkedList.next => next;
        }
    }
}
