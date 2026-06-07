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
                await using (var npcap = Core.Initialize().CreateNpcap())
                {
                    npcap.EnablePacketPrinting = true;
                    npcap.Events.PacketCaptured += (packet) =>
                    {
                        // Console.WriteLine($"Received: {packet.CaptureLenght}");
                    };

                    var deviceList1 = npcap.Devices.GetDevices();
                    var deviceList2 = npcap.Devices.GetDevices(p => p.Contains("Realtek RTL8852BE WiFi 6 802.11ax", StringComparison.OrdinalIgnoreCase));
                    var device = deviceList2.First();

                    var flagS = Native.WpcapDefs.PcapOpenOptions.PCAP_OPENFLAG_PROMISCUOUS |
                        Native.WpcapDefs.PcapOpenOptions.PCAP_OPENFLAG_NOCAPTURE_LOCAL |
                        Native.WpcapDefs.PcapOpenOptions.PCAP_OPENFLAG_MAX_RESPONSIVENESS;

                    device = npcap.Devices.OpenDevice(device, flagS);
                    var result = npcap.Capture.Capture(device, "tcp");
                    if (result.Success)
                    {
                        await Task.Delay(TimeSpan.FromSeconds(5));
                        await result.Joystick!.StopAsync();
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
