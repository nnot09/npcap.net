using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace npcap.net.Native
{
	// mainly used sdk and npcap docs here
	internal static class Wpcap
	{
		public const string PCAP_SRC_IF_STRING = "rpcap://";

		/*
		 PCAP_AVAILABLE_1_9_REMOTE
PCAP_API int	pcap_findalldevs_ex(const char *source,
		struct pcap_rmtauth *auth, pcap_if_t **alldevs, char *errbuf);
		 */

		// TODO maybe specify calling convention (__cdecl with high chance)
		[DllImport("wpcap.dll")]
		// public static extern IntPtr pcap_findalldevs_ex(string source, WpcapStructs.pcap_rmtauth auth, out IntPtr devices, out string errbuf);
		public static extern int pcap_findalldevs_ex(string source, IntPtr auth, out IntPtr devices, StringBuilder errbuf);

		[DllImport("wpcap.dll")]
		public static extern int pcap_findalldevs(out IntPtr devices, StringBuilder errbuf);
	}
}
