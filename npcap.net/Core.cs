using npcap.net.NewFolder;
using System.Security.Cryptography.X509Certificates;

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
                throw new NpcapNotInstalledException(isElevated.Reason ?? "Windows OS and administrative privileges are required.");
            }

            if (!Helpers.IsNpcapInstalled())
            {
                throw new NpcapNotInstalledException("Npcap is not installed or corrupted. Please visit https://npcap.com/#download to download and install it.");
            }

            IsReady = true;
        }

        public void Routine()
        {
            try
            {
                Console.Write($"{DateTime.Now} npcap.net: Loading npcap...");
                
                Npcap npcap = new Npcap();
                if (npcap.IsReady)
                {
                    Console.WriteLine("OK");
                }
                else
                {
                    Console.WriteLine("ERR");
                    return;
                }

                Console.Write($"{DateTime.Now} npcap.net: Running test...");
                var result = npcap.Test();
                if (result.Success)
                {
                    Console.WriteLine("OK");
                }
                else
                {
                    Console.WriteLine("ERR");
                    Console.WriteLine($"{DateTime.Now} npcap.net: {result.ErrorMessage}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{DateTime.Now} npcap.net: {ex.Message}");
            }
        }
    }
}
