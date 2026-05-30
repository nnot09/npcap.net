using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
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

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_create.html"/>
        /// </summary>
        /// <param name="source"></param>
        /// <param name="errbuf"></param>
        /// <returns>pcap_t* on success, NULL on failure. Evaluate <paramref name="errbuf"/> for error details.</returns>
        [DllImport("wpcap.dll")]
        public static extern IntPtr pcap_create(string source, StringBuilder errbuf);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_activate.html"/>
        /// </summary>
        /// <param name="pcap"></param>
        /// <returns>0 = success, above zero = success with warnings, below zero = failure. Please refer to the documentation for details.</returns>
        [DllImport("wpcap.dll")]
        public unsafe static extern int pcap_activate(WpcapStructs.pcap* pcap); // TODO add definition of error codes from docs

        /// <summary>
        /// 
        /// </summary>
        /// <param name="source"></param>
        /// <param name="auth"></param>
        /// <param name="devices"></param>
        /// <param name="errbuf"></param>
        /// <returns></returns>
        [DllImport("wpcap.dll")]
        public static extern int pcap_findalldevs_ex(string source, IntPtr auth, out IntPtr devices, StringBuilder errbuf);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_findalldevs.html"/>
        /// </summary>
        /// <param name="devices"></param>
        /// <param name="errbuf"></param>
        /// <returns>0 on success, -1 on failure. Please refer to the documentation for details.</returns>
        [DllImport("wpcap.dll")]
        public static extern int pcap_findalldevs(out IntPtr devices, StringBuilder errbuf);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="ptr"></param>
        [DllImport("wpcap.dll")]
        public static extern void pcap_freealldevs(IntPtr ptr);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_open_offline.html"/>
        /// </summary>
        /// <param name="name"></param>
        /// <param name="errbuf"></param>
        /// <returns>pcap* on success, NULL on failure. Evaluate <paramref name="errbuf"/> for error details.</returns>
        [DllImport("wpcap.dll")]
        public static extern IntPtr pcap_open_offline(string name, StringBuilder errbuf);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_open_offline.html"/>
        /// </summary>
        /// <param name="name"></param>
        /// <param name="errbuf"></param>
        /// <returns>pcap* on success, NULL on failure. Evaluate <paramref name="errbuf"/> for error details.</returns>
        [DllImport("wpcap.dll")]
        public static extern IntPtr pcap_open_offline_with_tstamp_precision(string name, uint precision, StringBuilder errbuf);
        /*
            pcap_t *pcap_fopen_offline(FILE *fp, char *errbuf);
            pcap_t *pcap_fopen_offline_with_tstamp_precision(FILE *fp,u_int precision, char *errbuf);
         */

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_open_dead.html"/>
        /// </summary>
        /// <param name="linktype"><see href="https://www.tcpdump.org/linktypes.html"/></param>
        /// <param name="snaplen"></param>
        /// <returns>Pointer to an object of pcap type</returns>
        [DllImport("wpcap.dll")]
        public static extern IntPtr pcap_open_dead(int linktype, int snaplen);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_open_dead.html"/>
        /// </summary>
        /// <param name="linktype"></param>
        /// <param name="snaplen"></param>
        /// <returns>Pointer to an object of pcap type</returns>
        [DllImport("wpcap.dll")]
        public static extern IntPtr pcap_open_dead_with_tstamp_precision(int linktype, int snaplen, uint precision);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_close.html"/>
        /// </summary>
        /// <param name="pcap"></param>
        [DllImport("wpcap.dll")]
        public unsafe static extern void pcap_close(WpcapStructs.pcap* pcap);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_set_snaplen.html"/>
        /// </summary>
        /// <param name="p"></param>
        /// <param name="snaplen"></param>
        /// <returns>0 on success, PCAP_ERROR_ACTIVATED (-4) on failure. Please refer to the documentation for details.</returns>
        public unsafe static extern int pcap_set_snaplen(WpcapStructs.pcap* p, int snaplen);
    }
}
