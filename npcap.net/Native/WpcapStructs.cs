using npcap.net.Native.Libraries;
using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static System.Net.WebRequestMethods;

namespace npcap.net.Native
{
    // mainly used SDK and online research
    internal static class WpcapStructs
    {
        /// <summary>
        /// Representation of an interface address.
        /// </summary>
        public unsafe struct pcap_addr
        {
            public pcap_addr* next;
            public Ws2_32.sockaddr* addr;     /* address */
            public Ws2_32.sockaddr* netmask;  /* netmask for that address */
            public Ws2_32.sockaddr* broadaddr;    /* broadcast address for that address */
            public Ws2_32.sockaddr* dstaddr;	/* P2P destination address for that address */
        };

        /*
        * Item in a list of interfaces.
 */
        // Credits Copilot for the idea to use an interface in combination with the next pointer.
        public unsafe interface ILinkedList
        {
            void* next { get; }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public unsafe struct pcap_if : ILinkedList
        {
            public pcap_if* next;
            public string name;     /* name to hand to "pcap_open_live()" */
            public string description;  /* textual description of interface, or NULL */
            public pcap_addr* addresses;
            public uint flags;  /* PCAP_IF_ interface flags */
            unsafe void* ILinkedList.next => next; // Copilot \_(°.°)_/
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct pcap_rmtauth
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
            string username;
            /*
             * \brief Zero-terminated string containing the password that has to be
             * used on the remote machine for authentication.
             *
             * This field is meaningless in case of the RPCAP_RMTAUTH_NULL authentication
             * and it can be NULL.
             */
            string password;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct pcap_samp
        {
            /*
             * Method used for sampling; see above.
             */
            int method;

            /*
             * This value depends on the sampling method defined.
             * For its meaning, see above.
             */
            int value;
        };

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct pcap_opt
        {
            public string device;
            public int timeout;    /* timeout for buffering */
            public uint buffer_size;
            public int promisc;
            public int rfmon;      /* monitor mode */
            public int immediate;  /* immediate mode - deliver packets as soon as they arrive */
            public int nonblock;   /* non-blocking mode - don't wait for packets to be delivered, return "no packets available" */
            public int tstamp_type;
            public int tstamp_precision;

            /*
             * Platform-dependent options.
             */
            //# ifdef __linux__
            //            int protocol;   /* protocol to use when creating PF_PACKET socket */
            //#endif
            //# ifdef _WIN32
            //            int nocapture_local;/* disable NPF loopback */
            //#endif
            public int nocapture_local; // for now Windows only
        };

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct pcap_stat
        {
            public uint ps_recv;      /* number of packets received */
            public uint ps_drop;      /* number of packets dropped */
            public uint ps_ifdrop;    /* drops by interface -- only supported on some platforms */
            public uint ps_capt;      /* number of packets that reach the application */
            public uint ps_sent;      /* number of packets sent by the server on the network */
            public uint ps_netdrop;   /* number of packets lost on the network */
        };

        public enum pcap_direction_t
        {
            PCAP_D_INOUT = 0,   /* capture all packets */
            PCAP_D_IN = 1,      /* capture "in" packets */
            PCAP_D_OUT = 2,     /* capture "out" packets */
        };

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct bpf_program
        {
            public uint bf_len;
            public bpf_insn* bf_insns;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct bpf_insn
        {
            ushort code;
            char jt;
            char jf;
            uint k;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct pcap_pkthdr
        {
            // public timeval ts;	/* time stamp */
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] ts;
            public uint caplen; /* length of portion present in data */
            public uint len;    /* length of this packet prior to any slicing */
        };


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public unsafe struct pcap
        {
            /*
             * Method to call to read packets on a live capture.
             */
            // read_op_t read_op;
            public read_op_t* read_op;

            /*
             * Method to call to read the next packet from a savefile.
             */
            // next_packet_op_t next_packet_op;
            public next_packet_op_t* next_packet_op;

            public IntPtr handle;

            /*
             * Read buffer.
             */
            public uint bufsize;
            public IntPtr buffer;
            public IntPtr bp;
            public uint cc;

            public int break_loop; /* flag set to force break from packet-reading loop */

            public IntPtr priv;     /* private data for methods */

            // TODO ENABLE_REMOTE
            public pcap_samp rmt_samp;  /* parameters related to the sampling process. */

            public int swapped;
            // FILE* rfile;        /* null if live capture, non-null if savefile */
            IntPtr rfile;
            public uint fddipad;
            public pcap* next;  /* list of open pcaps that need stuff cleared on close */

            /*
             * File version number; meaningful only for a savefile, but we
             * keep it here so that apps that (mistakenly) ask for the
             * version numbers will get the same zero values that they
             * always did.
             */
            public int version_major;
            public int version_minor;
            public int snapshot;
            public int linktype;       /* Network linktype */
            public int linktype_ext;   /* Extended information stored in the linktype field of a file */
            public uint offset;       /* offset for proper alignment */
            public int activated;      /* true if the capture is really started */
            public int oldstyle;       /* if we're opening with pcap_open_live() */

            public pcap_opt opt;

            /*
             * Place holder for pcap_next().
             */
            public string pkt;
            public pcap_stat stat;  /* used for pcap_stats_ex() */

            /* We're accepting only packets in this direction/these directions. */
            public pcap_direction_t direction;

            /*
             * Flags to affect BPF code generation.
             */
            public int bpf_codegen_flags;

#if false
if !defined(_WIN32)
            int selectable_fd;  /* FD on which select()/poll()/epoll_wait()/kevent()/etc. can be done */

            /*
             * In case there either is no selectable FD, or there is but
             * it doesn't necessarily work (e.g., if it doesn't get notified
             * if the packet capture timeout expires before the buffer
             * fills up), this points to a timeout that should be used
             * in select()/poll()/epoll_wait()/kevent() call.  The pcap_t should
             * be put into non-blocking mode, and, if the timeout expires on
             * the call, an attempt should be made to read packets from all
             * pcap_t's with a required timeout, and the code must be
             * prepared not to see any packets from the attempt.
             */
            const struct timeval *required_select_timeout;
#endif


            /*
             * Placeholder for filter code if bpf not in kernel.
             */
            public bpf_program fcode;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = WpcapDefs.PCAP_ERRBUF_SIZE + 1)] // PCAP_ERRBUF_SIZE
            public char[] errbuf;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = WpcapDefs.PCAP_ERRBUF_SIZE + 1)] // PCAP_ERRBUF_SIZE
            public char[] acp_errbuf;  /* buffer for local code page error strings */
            public int dlt_count;
            public uint* dlt_list;
            public int tstamp_type_count;
            public uint* tstamp_type_list;
            public int tstamp_precision_count;
            public uint* tstamp_precision_list;

            public pcap_pkthdr pcap_header; /* This is needed for the pcap_next_ex() to work */

            /*
             * More methods.
             */
            public pcap* activate_op;
            public pcap* can_set_rfmon_op;
            public inject_op_t* inject_op;
            public save_current_filter_op_t* save_current_filter_op;
            public setfilter_op_t* setfilter_op;
            public setdirection_op_t* setdirection_op;
            public set_datalink_op_t* set_datalink_op;
            public getnonblock_op_t* getnonblock_op;
            public setnonblock_op_t* setnonblock_op;
            public stats_op_t* stats_op;
            public breakloop_op_t* breakloop_op;

            /*
             * Routine to use as callback for pcap_next()/pcap_next_ex().
             */
            public pcap_handler* oneshot_callback;

            /*
             * These are, at least currently, specific to the Win32 NPF
             * driver.
             */
            public stats_ex_op_t stats_ex_op;
            public setbuff_op_t setbuff_op;
            public setmode_op_t setmode_op;
            public setmintocopy_op_t setmintocopy_op;
            public getevent_op_t getevent_op;
            public oid_get_request_op_t oid_get_request_op;
            public oid_set_request_op_t oid_set_request_op;
            public sendqueue_transmit_op_t sendqueue_transmit_op;
            public setuserbuffer_op_t setuserbuffer_op;
            public live_dump_op_t live_dump_op;
            public live_dump_ended_op_t live_dump_ended_op;
            public cleanup_op_t cleanup_op;
        };

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct next_packet_op_t
        {
            public pcap* pcap;
            public pcap_pkthdr* header;
            public IntPtr f1; // TODO char**
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct pcap_send_queue
        {
            public uint maxlen;   /* Maximum size of the queue, in bytes. This
			       variable contains the size of the buffer field. */
            public uint len;  /* Current size of the queue, in bytes. */
            public string buffer;   /* Buffer containing the packets to be sent. */
        };

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct cleanup_op_t
        {
            public pcap* pcap;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct live_dump_ended_op_t
        {
            public pcap* pcap;
            public int f1;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public unsafe struct live_dump_op_t
        {
            public pcap* pcap;
            public string f1;
            public int f2;
            public int f3;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct setuserbuffer_op_t
        {
            public pcap* pcap;
            public int f1;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct sendqueue_transmit_op_t
        {
            public pcap* pcap;
            public pcap_send_queue send_queue;
            public int f1;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct oid_set_request_op_t
        {
            public pcap* pcap;
            public uint f1;
            public void* f2;
            public int f3;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct oid_get_request_op_t
        {
            public pcap* pcap;
            public uint f1;
            public void* f2;
            public int f3;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct getevent_op_t
        {
            public pcap* pcap;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct setmintocopy_op_t
        {
            public pcap* pcap;
            public int f1;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct setmode_op_t
        {
            public pcap* pcap;
            public int f1;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct setbuff_op_t
        {
            public pcap* pcap;
            public int f1;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct stats_ex_op_t
        {
            public pcap* pcap;
            public IntPtr f1;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct breakloop_op_t
        {
            public pcap* pcap;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct stats_op_t
        {
            public pcap* pcap;
            public pcap_stat* stat;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct setnonblock_op_t
        {
            public pcap* pcap;
            public int f1;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct getnonblock_op_t
        {
            public pcap* pcap;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct set_datalink_op_t
        {
            public pcap* pcap;
            public int f1;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct setdirection_op_t
        {
            public pcap* pcap;
            public pcap_direction_t direction;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct setfilter_op_t
        {
            public pcap* pcap;
            public bpf_program* f1;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct save_current_filter_op_t
        {
            public pcap* pcap;
            public IntPtr f1;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct inject_op_t
        {
            public pcap* pcap;
            public void* f1;
            public int f2;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct read_op_t
        {
            public pcap* pcap;
            public int count;
            public pcap_handler handler;
            public IntPtr f1;
        }

        public unsafe struct pcap_handler
        {
            // Credits Copilot for this idea. Didn't know about this till now, I'll prefer type-safety
            public delegate* unmanaged[Stdcall]<pcap*, IntPtr, IntPtr, void> callback;
        }
    }
}
