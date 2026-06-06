using npcap.net.Bridge;
using npcap.net.Exceptions;

namespace npcap.net
{
    public class Core
    {
        public static bool IsInitalized { get; private set; }

        /// <summary>
        /// Initializes the Core class by checking certain things to ensure that npcap and it's components can run properly.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="ElevationRequiredException">Raised when application is not running with administrative privileges.</exception>
        /// <exception cref="NpcapNotInstalledException">Raised when Npcap is not installed or corrupted.</exception>
        public static Core? Initialize()
        {
            if (IsInitalized) return null;

            var isElevated = Helpers.IsElevated();
            if (!isElevated.IsTrue)
            {
                throw new ElevationRequiredException(isElevated.Reason ?? "Windows OS and administrative privileges are required.");
            }

            if (!Helpers.IsNpcapInstalled())
            {
                throw new NpcapNotInstalledException("Npcap is not installed or corrupted. Please visit https://npcap.com/#download to download and install it.");
            }


            IsInitalized = true;
            return new Core();
        }

        /// <summary>
        /// Creates an instance of the Npcap class. Ensure that the Core class is initialized before calling this method.
        /// </summary>
        /// <returns>Instance of <see cref="Npcap"/></returns>
        /// <exception cref="InvalidOperationException">Raised when the Core class is not initialized.</exception>
        public Npcap CreateNpcap()
        {
            if (!IsInitalized)
            {
                throw new InvalidOperationException("Software is not ready. Ensure that the system meets the requirements and try again.");
            }
            return new Npcap();
        }
    }
}
