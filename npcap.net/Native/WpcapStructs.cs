using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace npcap.net.Native
{
    // mainly used SDK and online research
    internal static class WpcapStructs
    {
        // found it somewhere but forgot the credits, thanks unknown hero!
        [StructLayout(LayoutKind.Sequential)]
        public struct sockaddr
        {
            public ushort sa_family;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 14)]
            public byte[] sa_data;
        }

        /*
 * Representation of an interface address.
 */
        public unsafe struct pcap_addr
        {
            pcap_addr *next;
        	sockaddr *addr;		/* address */
	        sockaddr *netmask;	/* netmask for that address */
	        sockaddr *broadaddr;	/* broadcast address for that address */
	        sockaddr *dstaddr;	/* P2P destination address for that address */
        };

        /*
 * Item in a list of interfaces.
 */
        // typedef u_int bpf_u_int32;

        // Credits Copilot for the idea to use an interface in combination with the next pointer.
        public unsafe interface ILinkedList 
        {
            void* next { get; }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public unsafe struct pcap_if : ILinkedList
        {
            public pcap_if *next;
	        public string name;     /* name to hand to "pcap_open_live()" */
            public string description;  /* textual description of interface, or NULL */
            public pcap_addr *addresses;
	        public uint flags;  /* PCAP_IF_ interface flags */
            unsafe void* ILinkedList.next => next; // Copilot \_(°.°)_/
        };

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct pcap_rmtauth
        {
            /*
             * \brief Type of the authentication required.
             *
             * In order to provide maximum flexibility, we can support different types
             * of authentication based on the value of this 'type' variable. The currently
             * supported authentication methods are defined into the
             * \link remote_auth_methods Remote Authentication Methods Section\endlink.
             */
            int type;
            /*
             * \brief Zero-terminated string containing the username that has to be
             * used on the remote machine for authentication.
             *
             * This field is meaningless in case of the RPCAP_RMTAUTH_NULL authentication
             * and it can be NULL.
             */
            char* username; // TODO maybe "string" is enough here?
            /*
             * \brief Zero-terminated string containing the password that has to be
             * used on the remote machine for authentication.
             *
             * This field is meaningless in case of the RPCAP_RMTAUTH_NULL authentication
             * and it can be NULL.
             */
            char* password; // TODO maybe "string" is enough here?
        };

    }
}
