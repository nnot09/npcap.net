using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace npcap.net.Native
{
    internal static class WpcapDefs
    {
        public static int PCAP_IF_LOOPBACK = 0x00000001;    /* interface is loopback */
        public static int PCAP_IF_UP = 0x00000002;  /* interface is up */
        public static int PCAP_IF_RUNNING = 0x00000004; /* interface is running */
        public static int PCAP_IF_WIRELESS = 0x00000008;    /* interface is wireless (*NOT* necessarily Wi-Fi!) */
        public static int PCAP_IF_CONNECTION_STATUS = 0x00000030;   /* connection status: */
        public static int PCAP_IF_CONNECTION_STATUS_UNKNOWN = 0x00000000;   /* unknown */
        public static int PCAP_IF_CONNECTION_STATUS_CONNECTED = 0x00000010; /* connected */
        public static int PCAP_IF_CONNECTION_STATUS_DISCONNECTED = 0x00000020;  /* disconnected */
        public static int PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE = 0x00000030;	/* not applicable */
        public const int PCAP_ERRBUF_SIZE = 256;
    }

    // mainly used sdk and npcap docs here
    internal static class Wpcap
    {
        public const string PCAP_SRC_IF_STRING = "rpcap://";

        /*
		 PCAP_AVAILABLE_1_9_REMOTE
PCAP_API int	pcap_findalldevs_ex(const char *source,
		struct pcap_rmtauth *auth, pcap_if_t **alldevs, char *errbuf);
		 */

        [DllImport("wpcap.dll")]
        public static extern int pcap_findalldevs_ex(string source, IntPtr auth, out IntPtr devices, StringBuilder errbuf);

        [DllImport("wpcap.dll")]
        public static extern int pcap_findalldevs(out IntPtr devices, StringBuilder errbuf);

        [DllImport("wpcap.dll")]
        public static extern void pcap_freealldevs(IntPtr ptr);
    }
}
