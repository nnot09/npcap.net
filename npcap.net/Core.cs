using npcap.net.Exceptions;

namespace npcap.net
{
    public class Core
    {
        public bool IsReady { get; private set; }

        public Core()
        {
            var isElevated = Helpers.IsElevated();
            if (!isElevated.IsTrue)
            {
                throw new ElevationRequiredException(isElevated.Reason ?? "Windows OS and administrative privileges are required.");
            }

            if (!Helpers.IsNpcapInstalled())
            {
                throw new NpcapNotInstalledException("Npcap is not installed or corrupted. Please visit https://npcap.com/#download to download and install it.");
            }

            IsReady = true;
        }

        public Npcap Create()
        {
            if (!IsReady)
            {
                throw new InvalidOperationException("Software is not ready. Ensure that the system meets the requirements and try again.");
            }
            return new Npcap();
        }
    }
}
