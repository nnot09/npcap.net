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
        [DllImport("wpcap.dll")]
        public unsafe static extern int pcap_set_snaplen(WpcapStructs.pcap* p, int snaplen);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_snapshot.html"/>
        /// </summary>
        /// <param name="p"></param>
        /// <returns>snapshot length on success or PCAP_ERROR_NOT_ACTIVATED (-3) on failure. Please refer to the documentation for details.</returns>
        [DllImport("wpcap.dll")]
        public unsafe static extern int pcap_snapshot(WpcapStructs.pcap* p);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_set_promisc.html"/>
        /// </summary>
        /// <param name="p"></param>
        /// <param name="promisc"></param>
        /// <returns>0 on success, PCAP_ERROR_ACTIVATED (-4) on failure. Please refer to the documentation for details.</returns>
        [DllImport("wpcap.dll")]
        public unsafe static extern int pcap_set_promisc(WpcapStructs.pcap* p, int promisc);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_set_rfmon.html"/>
        /// </summary>
        /// <param name="p"></param>
        /// <param name="rfmon"></param>
        /// <returns>0 on success, PCAP_ERROR_ACTIVATED (-4) on failure. Please refer to the documentation for details.</returns>
        [DllImport("wpcap.dll")]
        public unsafe static extern int pcap_set_rfmon(WpcapStructs.pcap* p, int rfmon);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_can_set_rfmon.html"/>
        /// </summary>
        /// <param name="p"></param>
        /// <returns>returns 0 if monitor mode could not be set, 1 if monitor mode could be set, and a negative value on error. A negative return value indicates what error condition occurred. Please refer to the documentation for details.</returns>
        [DllImport("wpcap.dll")]
        public unsafe static extern int pcap_can_set_rfmon(WpcapStructs.pcap* p);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_set_timeout.html"/>
        /// </summary>
        /// <param name="p"></param>
        /// <param name="to_ms"></param>
        /// <returns>0 on success, PCAP_ERROR_ACTIVATED (-4) on failure. Please refer to the documentation for details.</returns>
        [DllImport("wpcap.dll")]
        public unsafe static extern int pcap_set_timeout(WpcapStructs.pcap* p, int to_ms);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_set_buffer_size.html"/>
        /// </summary>
        /// <param name="p"></param>
        /// <param name="buffer_size"></param>
        /// <returns>0 on success, PCAP_ERROR_ACTIVATED (-4) on failure. Please refer to the documentation for details.</returns>
        [DllImport("wpcap.dll")]
        public unsafe extern static int pcap_set_buffer_size(WpcapStructs.pcap* p, int buffer_size);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_set_tstamp_type.html"/>
        /// </summary>
        /// <param name="p"></param>
        /// <param name="tstamp_type"></param>
        /// <returns>0 on success. Please refer to the documentation for details.</returns>
        [DllImport("wpcap.dll")]
        public unsafe extern static int pcap_set_tstamp_type(WpcapStructs.pcap* p, int tstamp_type);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_list_tstamp_types.html"/>
        /// </summary>
        /// <param name="p"></param>
        /// <param name="tstamp_types"></param>
        /// <returns></returns>
        [DllImport("wpcap.dll")]
        public unsafe extern static int pcap_list_tstamp_types(WpcapStructs.pcap* p, out IntPtr tstamp_types);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_list_tstamp_types.html"/>
        /// </summary>
        /// <param name="tstamp_types"></param>
        [DllImport("wpcap.dll")]
        public extern static void pcap_free_tstamp_types(IntPtr tstamp_types);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_tstamp_type_val_to_name.html"/>
        /// </summary>
        /// <param name="tstamp_type"></param>
        /// <returns></returns>
        [DllImport("wpcap.dll")]
        public extern static string pcap_tstamp_type_val_to_name(int tstamp_type);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_tstamp_type_val_to_name.html"/>
        /// </summary>
        /// <param name="tstamp_type"></param>
        /// <returns></returns>
        [DllImport("wpcap.dll")]
        public extern static string pcap_tstamp_type_val_to_description(int tstamp_type);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_tstamp_type_name_to_val.html"/>
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        [DllImport("wpcap.dll")]
        public extern static int pcap_tstamp_type_name_to_val(string name);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_set_tstamp_precision.html"/>
        /// </summary>
        /// <param name="p"></param>
        /// <param name="precision"></param>
        /// <returns></returns>
        [DllImport("wpcap.dll")]
        public unsafe extern static int pcap_set_tstamp_precision(WpcapStructs.pcap* p, int precision);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_list_tstamp_precisions.html"/>
        /// </summary>
        /// <param name="p"></param>
        /// <returns></returns>
        [DllImport("wpcap.dll")]
        public unsafe extern static int pcap_get_tstamp_precision(WpcapStructs.pcap* p);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_datalink.html"/>
        /// </summary>
        /// <param name="p"></param>
        /// <returns></returns>
        [DllImport("wpcap.dll")]
        public unsafe extern static int pcap_datalink(WpcapStructs.pcap* p);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_file.html"/>
        /// </summary>
        /// <param name="p"></param>
        /// <returns>FILE*</returns>
        [DllImport("wpcap.dll")]
        public unsafe extern static IntPtr pcap_file(WpcapStructs.pcap* p);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_is_swapped.html"/>
        /// </summary>
        /// <param name="p"></param>
        /// <returns></returns>
        [DllImport("wpcap.dll")]
        public unsafe extern static int pcap_is_swapped(WpcapStructs.pcap* p);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_major_version.html"/>
        /// </summary>
        /// <param name="p"></param>
        /// <returns></returns>
        [DllImport("wpcap.dll")]
        public unsafe extern static int pcap_major_version(WpcapStructs.pcap* p);

        /// <summary>
        /// <see href="https://npcap.com/guide/wpcap/pcap_major_version.html"/>
        /// </summary>
        /// <param name="p"></param>
        /// <returns></returns>
        [DllImport("wpcap.dll")]
        public unsafe extern static int pcap_minor_version(WpcapStructs.pcap* p);
    }
}
