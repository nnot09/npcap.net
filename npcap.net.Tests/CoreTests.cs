using npcap.net.Exceptions;

namespace npcap.net.Tests
{
    /// <summary>
    /// Tests for <see cref="Core"/> that can run without Npcap installed or elevated
    /// privileges by covering guard-clause paths only.
    /// </summary>
    [TestClass]
    public class CoreTests
    {
        [TestInitialize]
        public void ResetCoreState()
        {
            // Core.IsInitalized is a static property; reset it via reflection so each
            // test starts from a clean state.
            typeof(Core)
                .GetProperty(nameof(Core.IsInitalized))!
                .SetValue(null, false);
        }

        [TestMethod]
        public void CreateNpcap_ThrowsInvalidOperationException_WhenNotInitialized()
        {
            var core = (Core)System.Runtime.CompilerServices.RuntimeHelpers
                .GetUninitializedObject(typeof(Core));

            Assert.ThrowsExactly<InvalidOperationException>(() => core.CreateNpcap());
        }

        [TestMethod]
        public void Initialize_ReturnsNull_WhenAlreadyInitialized()
        {
            // Force IsInitalized = true without going through the real Initialize path
            typeof(Core)
                .GetProperty(nameof(Core.IsInitalized))!
                .SetValue(null, true);

            var result = Core.Initialize();

            Assert.IsNull(result);
        }

        [TestMethod]
        [TestCategory("RequiresElevation")]
        public void Initialize_ThrowsElevationOrNpcapException_WhenNotElevated()
        {
            // This test is only meaningful when the process is NOT elevated.
            var (isElevated, _) = Helpers.IsElevated();
            if (isElevated)
            {
                Assert.Inconclusive("Process is elevated; skipping non-elevation guard test.");
            }

            Assert.ThrowsExactly<ElevationRequiredException>(() => Core.Initialize());
        }
    }
}
