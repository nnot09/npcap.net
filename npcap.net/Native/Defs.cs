using System;
using System.Collections.Generic;
using System.Text;

namespace npcap.net.Native
{
    // Credits: https://www.pinvoke.net
    internal static class Defs
    {
        [System.Flags]
        public enum LoadLibraryFlags : uint
        {
            DONT_RESOLVE_DLL_REFERENCES = 0x00000001,
            LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x00000010,
            LOAD_LIBRARY_AS_DATAFILE = 0x00000002,
            LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x00000040,
            LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020,
            LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200,
            LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100,
            LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800,
            LOAD_LIBRARY_SEARCH_USER_DIRS = 0x00000400,
            LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008
        }

        // Credits Copilot
        //[Flags]
        //public enum AddressFamily : ushort
        //{
        //    AF_UNSPEC = 0,      // Unspecified
        //    AF_UNIX = 1,        // Local to host (pipes, portals)
        //    AF_INET = 2,        // IPv4
        //    AF_IMPLINK = 3,     // ARPANET IMP addresses
        //    AF_PUP = 4,         // PUP protocols
        //    AF_CHAOS = 5,       // MIT CHAOS protocols
        //    AF_IPX = 6,         // IPX and SPX
        //    AF_NS = 6,          // XEROX NS protocols
        //    AF_ISO = 7,         // ISO protocols
        //    AF_OSI = 7,         // OSI is ISO
        //    AF_ECMA = 8,        // European Computer Manufacturers
        //    AF_DATAKIT = 9,     // Datakit protocols
        //    AF_CCITT = 10,      // CCITT protocols, X.25 etc
        //    AF_SNA = 11,        // IBM SNA
        //    AF_DECnet = 12,     // DECnet
        //    AF_DLI = 13,        // Direct data link interface
        //    AF_LAT = 14,        // LAT
        //    AF_HYLINK = 15,     // NSC Hyperchannel
        //    AF_APPLETALK = 16,  // AppleTalk
        //    AF_NETBIOS = 17,    // NetBios-style addresses
        //    AF_VOICEVIEW = 18,  // VoiceView
        //    AF_FIREFOX = 19,    // FireFox
        //    AF_UNKNOWN1 = 20,   // Somebody is using this!
        //    AF_BAN = 21,        // Banyan
        //    AF_ATM = 22,        // Native ATM Services
        //    AF_INET6 = 23,      // IPv6
        //    AF_CLUSTER = 24,    // Microsoft Wolfpack
        //    AF_12844 = 25,      // IEEE 1284.4 WG AF
        //    AF_IRDA = 26,       // IrDA
        //    AF_NETDES = 28,     // Network Designers OSI & gateway
        //    AF_MAX = 29
        //}
    }
}
