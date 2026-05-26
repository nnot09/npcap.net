namespace npcap.net.Runner
{
    internal class Program
    {
        static void Main(string[] args)
        {
            try
            {
                var npcap = new npcap.net.Core();
                npcap.Routine();
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
