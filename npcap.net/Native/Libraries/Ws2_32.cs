using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace npcap.net.Native.Libraries
{
    // ws2_32.dll - Credits to Copilot for implementation.
    internal static class Ws2_32
    {
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct sockaddr
        {
            [MarshalAs(UnmanagedType.U2)]
            public AddressFamily sa_family;
            //public ushort sa_family;

            //[MarshalAs(UnmanagedType.ByValArray, SizeConst = 14)]
            //public byte[] sa_data;
            public fixed byte sa_data[14];
        }

        // IPv4 socket address structure
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct sockaddr_in
        {
            public ushort sin_family;      // Address family (AF_INET = 2)
            public ushort sin_port;        // Port number (network byte order)
            public in_addr sin_addr;       // IPv4 address

            //[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            //public byte[] sin_zero;        // Padding to match sockaddr size
            public fixed byte sin_zero[8];
        }

        // IPv4 address structure
        [StructLayout(LayoutKind.Sequential)]
        public struct in_addr
        {
            public uint s_addr;            // IPv4 address (network byte order)
        }

        // IPv6 socket address structure
        [StructLayout(LayoutKind.Sequential)]
        public struct sockaddr_in6
        {
            public ushort sin6_family;     // Address family (AF_INET6 = 23)
            public ushort sin6_port;       // Port number (network byte order)
            public uint sin6_flowinfo;     // IPv6 flow information
            public in6_addr sin6_addr;     // IPv6 address
            public uint sin6_scope_id;     // Scope ID
        }

        // IPv6 address structure
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct in6_addr
        {
            //[MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            //public byte[] s6_addr;         // 128-bit IPv6 address
            public fixed byte s6_addr[16];
        }
    }
}
