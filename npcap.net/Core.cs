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

                Console.WriteLine($"{DateTime.Now} npcap.net: Running tests");
                var result = npcap.Test();
                if (result.Success)
                {
                    Console.WriteLine("Test successful.");
                }
                else
                {
                    Console.WriteLine("Test failed.");
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
