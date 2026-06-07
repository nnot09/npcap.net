using npcap.net;

namespace npcap.net.Tests
{
    [TestClass]
    public class GlobalTests
    {
        [TestMethod]
        public void InitializeLoggingLevels_None_DisablesAllLevels()
        {
            Global.InitializeLoggingLevels(MinimumLoggingLevel.None);

            Assert.IsFalse(Global.ShouldLogDebug);
            Assert.IsFalse(Global.ShouldLogWarning);
            Assert.IsFalse(Global.ShouldLogError);
            Assert.IsFalse(Global.ShouldLogFull);
        }

        [TestMethod]
        public void InitializeLoggingLevels_Debug_EnablesAllLevels()
        {
            Global.InitializeLoggingLevels(MinimumLoggingLevel.Debug);

            Assert.IsTrue(Global.ShouldLogDebug);
            Assert.IsTrue(Global.ShouldLogWarning);
            Assert.IsTrue(Global.ShouldLogError);
            Assert.IsTrue(Global.ShouldLogFull);
        }

        [TestMethod]
        public void InitializeLoggingLevels_Full_EnablesAllLevels()
        {
            Global.InitializeLoggingLevels(MinimumLoggingLevel.Full);

            Assert.IsTrue(Global.ShouldLogDebug);
            Assert.IsTrue(Global.ShouldLogWarning);
            Assert.IsTrue(Global.ShouldLogError);
            Assert.IsTrue(Global.ShouldLogFull);
        }

        [TestMethod]
        public void InitializeLoggingLevels_Warning_EnablesWarningAndError()
        {
            Global.InitializeLoggingLevels(MinimumLoggingLevel.Warning);

            Assert.IsFalse(Global.ShouldLogDebug);
            Assert.IsTrue(Global.ShouldLogWarning);
            Assert.IsTrue(Global.ShouldLogError);
        }

        [TestMethod]
        public void InitializeLoggingLevels_Error_EnablesOnlyError()
        {
            Global.InitializeLoggingLevels(MinimumLoggingLevel.Error);

            Assert.IsFalse(Global.ShouldLogDebug);
            Assert.IsFalse(Global.ShouldLogWarning);
            Assert.IsTrue(Global.ShouldLogError);
        }
    }
}
