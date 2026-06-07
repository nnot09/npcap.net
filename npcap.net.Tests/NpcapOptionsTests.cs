namespace npcap.net.Tests
{
    [TestClass]
    public class NpcapOptionsTests
    {
        [TestMethod]
        public void Default_EnablePacketPrinting_IsFalse()
        {
            Assert.IsFalse(new NpcapOptions().Default.EnablePacketPrinting);
        }

        [TestMethod]
        public void Default_CreateDumpFile_IsTrue()
        {
            Assert.IsTrue(new NpcapOptions().Default.CreateDumpFile);
        }

        [TestMethod]
        public void Default_DumpFileBehaviour_IsWriteThreshold()
        {
            Assert.AreEqual(DumpFileBehaviour.WriteThreshold, new NpcapOptions().Default.DumpFileBehaviour);
        }

        [TestMethod]
        public void Default_DumpFileRollingMode_IsRollBySize()
        {
            Assert.AreEqual(DumpFileRollingMode.RollBySize, new NpcapOptions().Default.DumpFileRollingMode);
        }

        [TestMethod]
        public void Default_OutputDirectory_IsUnderAppData()
        {
            var expected = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "npcap.net");
            Assert.AreEqual(expected, new NpcapOptions().Default.OutputDirectory);
        }

        [TestMethod]
        public void Default_InternalPacketBufferSizeThreshold_Is1024()
        {
            Assert.AreEqual(1024L, new NpcapOptions().Default.DumpFileInternalPacketBufferSizeThreshold);
        }

        [TestMethod]
        public void Default_PacketSizeThresholdUnit_IsKiB()
        {
            Assert.AreEqual(SizeUnit.KiB, new NpcapOptions().Default.DumpFilePacketSizeThresholdUnit);
        }

        [TestMethod]
        public void Default_DumpFileSizeThreshold_Is512()
        {
            Assert.AreEqual(512L, new NpcapOptions().Default.DumpFileSizeThreshold);
        }

        [TestMethod]
        public void Default_RollingSizeThreshold_IsMiB()
        {
            Assert.AreEqual(SizeUnit.MiB, new NpcapOptions().Default.DumpFileRollingSizeThreshold);
        }

        [TestMethod]
        public void Default_EachCall_ReturnsNewInstance()
        {
            var a = new NpcapOptions().Default;
            var b = new NpcapOptions().Default;
            Assert.AreNotSame(a, b);
        }

        [TestMethod]
        public void NpcapOptions_MutatingProperty_DoesNotAffectDefault()
        {
            var opts = new NpcapOptions();
            opts.EnablePacketPrinting = true;
            opts.CreateDumpFile = false;

            // Default is computed fresh each time; mutations on opts must not bleed through
            Assert.IsFalse(opts.Default.EnablePacketPrinting);
            Assert.IsTrue(opts.Default.CreateDumpFile);
        }
    }

    [TestClass]
    public class SizeUnitTests
    {
        [TestMethod]
        public void SizeUnit_Values_AreOrdered()
        {
            // Byte < KiB < MiB < GiB < TiB — use variables to suppress constant-folding warnings
            int[] order = [(int)SizeUnit.Byte, (int)SizeUnit.KiB, (int)SizeUnit.MiB, (int)SizeUnit.GiB, (int)SizeUnit.TiB];
            for (int i = 1; i < order.Length; i++)
            {
                Assert.IsTrue(order[i - 1] < order[i], $"Expected {(SizeUnit)(i - 1)} < {(SizeUnit)i}");
            }
        }

        [TestMethod]
        public void SizeUnit_AllValues_Defined()
        {
            var values = Enum.GetValues<SizeUnit>();
            CollectionAssert.Contains(values, SizeUnit.Byte);
            CollectionAssert.Contains(values, SizeUnit.KiB);
            CollectionAssert.Contains(values, SizeUnit.MiB);
            CollectionAssert.Contains(values, SizeUnit.GiB);
            CollectionAssert.Contains(values, SizeUnit.TiB);
        }
    }

    [TestClass]
    public class DumpFileBehaviourTests
    {
        [TestMethod]
        public void DumpFileBehaviour_AllValues_Defined()
        {
            var values = Enum.GetValues<DumpFileBehaviour>();
            CollectionAssert.Contains(values, DumpFileBehaviour.WritePerPacket);
            CollectionAssert.Contains(values, DumpFileBehaviour.WriteThreshold);
        }
    }

    [TestClass]
    public class DumpFileRollingModeTests
    {
        [TestMethod]
        public void DumpFileRollingMode_AllValues_Defined()
        {
            var values = Enum.GetValues<DumpFileRollingMode>();
            CollectionAssert.Contains(values, DumpFileRollingMode.RollBySize);
            CollectionAssert.Contains(values, DumpFileRollingMode.RollDaily);
        }
    }
}
