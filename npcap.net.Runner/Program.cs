using npcap.net.ManagedTypes;
using System.Reflection;

namespace npcap.net.Runner
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            try
            {
                var npcapCore = new Core();
                using (var npcap = npcapCore.Create())
                {
                    npcap.PacketCaptured += ((s, p) =>
                    {
                        if (p.ContentsHex.Length > 100)
                        {
                            Console.WriteLine(p.ContentsHex.Substring(0, 100) + " ...");
                        }
                        else
                        {
                            Console.WriteLine(p.ContentsHex);
                        }

                    });

                    var deviceList1 = npcap.GetDevices();
                    var deviceList2 = npcap.GetDevices(p => p.Contains("Realtek RTL8852BE WiFi 6 802.11ax", StringComparison.OrdinalIgnoreCase));
                    var device = deviceList2.First();

                    var flagS = Native.WpcapDefs.PcapOpenOptions.PCAP_OPENFLAG_PROMISCUOUS |
                        Native.WpcapDefs.PcapOpenOptions.PCAP_OPENFLAG_NOCAPTURE_LOCAL |
                        Native.WpcapDefs.PcapOpenOptions.PCAP_OPENFLAG_MAX_RESPONSIVENESS;

                    device = npcap.OpenDevice(device, flagS);
                    var capTask = npcap.Capture(device, "tcp");
                    if (capTask.Success)
                    {
                        await Task.Delay(TimeSpan.FromSeconds(30));
                        capTask.CancellationTokenSource.Cancel();
                        capTask.Task.Dispose();
                    }
                }

                Console.WriteLine("Completed.");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error: {ex.Message}");
                Console.ResetColor();
            }

            Console.WriteLine($"{DateTime.Now} executed from host. press any key to exit.");
            Console.Read();
        }
    }
}
