using npcap.net.ManagedTypes;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Net.Sockets;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Unicode;
using System.Timers;
using static npcap.net.Native.WpcapStructs;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace npcap.net.Native
{
    public static class WpcapDefs
    {
        [Flags]
        public enum InterfaceFlags : int
        {
            /// <summary>
            /// interface is loopback
            /// </summary>
            PCAP_IF_LOOPBACK = 0x00000001,
            /// <summary>
            /// interface is up
            /// </summary>
            PCAP_IF_UP = 0x00000002,
            /// <summary>
            /// interface is running
            /// </summary>
            PCAP_IF_RUNNING = 0x00000004,
            /// <summary>
            /// interface is wireless (*NOT* necessarily Wi-Fi!)
            /// </summary>
            PCAP_IF_WIRELESS = 0x00000008,
            /// <summary>
            /// connection status
            /// </summary>
            PCAP_IF_CONNECTION_STATUS = 0x00000030,
            /// <summary>
            /// unknown connection status
            /// </summary>
            PCAP_IF_CONNECTION_STATUS_UNKNOWN = 0x00000000,
            /// <summary>
            /// connected
            /// </summary>
            PCAP_IF_CONNECTION_STATUS_CONNECTED = 0x00000010,
            /// <summary>
            /// disconnected
            /// </summary>
            PCAP_IF_CONNECTION_STATUS_DISCONNECTED = 0x00000020,
            /// <summary>
            /// not applicable
            /// </summary>
            PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE = 0x00000030
        }

        /// <summary>
        /// Flags to pass to pcap_open().
        /// </summary>
        public enum PcapOpenOptions : int
        {
            /// <summary>
            /// Specifies whether promiscuous mode is to be used.
            /// </summary>
            PCAP_OPENFLAG_PROMISCUOUS = 0x00000001,

            /// <summary>
            /// Specifies, for an RPCAP capture, whether the data transfer(in case of a remote capture) has to be done with UDP protocol.<br/>
            /// <br/>
            /// If it is '1' if you want a UDP data connection, '0' if you want<br/>
            /// a TCP data connection; control connection is always TCP-based.<br/>
            /// A UDP connection is much lighter, but it does not guarantee that all<br/>
            /// the captured packets arrive to the client workstation.Moreover,<br/>
            /// it could be harmful in case of network congestion.<br/>
            /// This flag is meaningless if the source is not a remote interface.<br/>
            /// In that case, it is simply ignored.<br/>
            /// </summary>
            PCAP_OPENFLAG_DATATX_UDP = 0x00000002,

            /// <summary>
            /// Specifies whether the remote probe will capture its own generated traffic.<br/>
            /// <br/>
            /// In case the remote probe uses the same interface to capture traffic<br/>
            /// and to send data back to the caller, the captured traffic includes<br/>
            /// the RPCAP traffic as well.If this flag is turned on, the RPCAP<br/>
            /// traffic is excluded from the capture, so that the trace returned<br/>
            /// back to the collector is does not include this traffic.<br/>
            /// <br/>
            /// Has no effect on local interfaces or savefiles.<br/>
            /// </summary>
            PCAP_OPENFLAG_NOCAPTURE_RPCAP = 0x00000004,

            /// <summary>
            /// Specifies whether the local adapter will capture its own generated traffic.<br/>
            /// <br/>
            /// This flag tells the underlying capture driver to drop the packets<br/>
            /// that were sent by itself.  This is useful when building applications<br/>
            /// such as bridges that should ignore the traffic they just sent.<br/>
            /// <br/>
            /// Supported only on Windows.<br/>
            /// </summary>
            PCAP_OPENFLAG_NOCAPTURE_LOCAL = 0x00000008,

            /// <summary>
            /// This flag configures the adapter for maximum responsiveness.<br/>
            /// <br/>
            /// In presence of a large value for nbytes, WinPcap waits for the arrival<br/>
            /// of several packets before copying the data to the user. This guarantees<br/>
            /// a low number of system calls, i.e. lower processor usage, i.e. better<br/>
            /// performance, which is good for applications like sniffers. If the user<br/>
            /// sets the PCAP_OPENFLAG_MAX_RESPONSIVENESS flag, the capture driver will<br/>
            /// copy the packets as soon as the application is ready to receive them.<br/>
            /// This is suggested for real time applications (such as, for example,<br/>
            /// a bridge) that need the best responsiveness.<br/>
            /// <br/>
            /// The equivalent with pcap_create()/pcap_activate() is "immediate mode".<br/>
            /// </summary>
            PCAP_OPENFLAG_MAX_RESPONSIVENESS = 0x00000010
        }

        /// <summary>
        /// Remote authentication methods.<br/>
        /// These are used in the 'type' member of the pcap_rmtauth structure.<br/>
        /// </summary>
        public static class RemoteAuthenticationMethods
        {
            /// <summary>
            /// NULL authentication.<br/>
            /// <br/>
            /// The 'NULL' authentication has to be equal to 'zero', so that old<br/>
            /// applications can just put every field of struct pcap_rmtauth to zero,<br/>
            /// and it does work.<br/>
            /// </summary>
            public static int RPCAP_RMTAUTH_NULL = 0;

            /// <summary>
            /// Username/password authentication.<br/>
            /// <br/>
            /// With this type of authentication, the RPCAP protocol will use the username/<br/>
            /// password provided to authenticate the user on the remote machine. If the<br/>
            /// authentication is successful (and the user has the right to open network<br/>
            /// devices) the RPCAP connection will continue; otherwise it will be dropped.<br/>
            /// <br/>
            /// *******NOTE********: unless TLS is being used, the username and password<br/>
            /// are sent over the network to the capture server *IN CLEAR TEXT*.  Don't<br/>
            /// use this, without TLS (i.e., with rpcap:// rather than rpcaps://) on<br/>
            /// a network that you don't completely control!  (And be *really* careful<br/>
            /// in your definition of "completely"!)<br/>
            /// </summary>
            public static int RPCAP_RMTAUTH_PWD = 1;
        }

        /// <summary>
        /// URL schemes for capture source.
        /// </summary>
        public static class CaptureSource
        {
            /// <summary>
            /// This string indicates that the user wants to open a capture from a local file.
            /// </summary>
            public const string PCAP_SRC_FILE_STRING = "file://";

            /// <summary>
            /// This string indicates that the user wants to open a capture from a <br/>
            /// network interface. This string does not necessarily involve the use<br/>
            /// of the RPCAP protocol.If the interface required resides on the local<br/>
            /// host, the RPCAP protocol is not involved and the local functions are used.<br/>
            /// </summary>
            public const string PCAP_SRC_IF_STRING = "rpcap://";  /* remote capture */
        }

        /// <summary>
        /// Initialization options.<br/>
        /// All bits not listed here are reserved for expansion.<br/>
        /// <br/>
        /// On UNIX - like systems, the local character encoding is assumed to be<br/>
        /// UTF - 8, so no character encoding transformations are done.<br/>
        /// <br/>
        /// On Windows, the local character encoding is the local ANSI code page.<br/>
        /// </summary>
        public static class PcapInitializationOptions
        {
            /// <summary>
            /// strings are in the local character encoding
            /// </summary>
            public const uint PCAP_CHAR_ENC_LOCAL = 0x00000000U;

            /// <summary>
            /// strings are in UTF-8
            /// </summary>
            public const uint PCAP_CHAR_ENC_UTF_8 = 0x00000001U;
        }

        public static class General
        {
            /// <summary>
            /// Value to pass to pcap_compile() as the netmask if you don't know what the netmask is.
            /// </summary>
            public const uint PCAP_NETMASK_UNKNOWN = 0xffffffff;

            public const int PCAP_ERRBUF_SIZE = 256;
        }

        /// <summary>
        /// Time stamp types.<br/>
        /// Not all systems and interfaces will necessarily support all of these.<br/>
        /// <br/>
        /// A system that supports PCAP_TSTAMP_HOST is offering time stamps<br/>
        /// provided by the host machine, rather than by the capture device,<br/>
        /// but not committing to any characteristics of the time stamp.<br/>
        /// <br/>
        /// PCAP_TSTAMP_HOST_LOWPREC is a time stamp, provided by the host machine,<br/>
        /// that's low-precision but relatively cheap to fetch; it's normally done<br/>
        /// using the system clock, so it's normally synchronized with times you'd<br/>
        /// fetch from system calls.<br/>
        /// <br/>
        /// PCAP_TSTAMP_HOST_HIPREC is a time stamp, provided by the host machine,<br/>
        /// that's high-precision; it might be more expensive to fetch. It is<br/>
        /// synchronized with the system clock.<br/>
        /// <br/>
        /// PCAP_TSTAMP_HOST_HIPREC_UNSYNCED is a time stamp, provided by the host<br/>
        /// machine, that's high-precision; it might be more expensive to fetch.<br/>
        /// It is not synchronized with the system clock, and might have<br/>
        /// problems with time stamps for packets received on different CPUs,<br/>
        /// depending on the platform.It might be more likely to be strictly<br/>
        /// monotonic than PCAP_TSTAMP_HOST_HIPREC.<br/>
        /// <br/>
        /// PCAP_TSTAMP_ADAPTER is a high-precision time stamp supplied by the<br/>
        /// capture device; it's synchronized with the system clock.<br/>
        /// <br/>
        /// PCAP_TSTAMP_ADAPTER_UNSYNCED is a high-precision time stamp supplied by<br/>
        /// the capture device; it's not synchronized with the system clock.<br/>
        /// <br/>
        /// Note that time stamps synchronized with the system clock can go<br/>
        /// backwards, as the system clock can go backwards.If a clock is<br/>
        /// not in sync with the system clock, that could be because the<br/>
        /// system clock isn't keeping accurate time, because the other<br/>
        /// clock isn't keeping accurate time, or both.<br/>
        /// <br/>
        /// Note that host-provided time stamps generally correspond to the<br/>
        /// time when the time-stamping code sees the packet; this could<br/>
        /// be some unknown amount of time after the first or last bit of<br/>
        /// the packet is received by the network adapter, due to batching<br/>
        /// of interrupts for packet arrival, queueing delays, etc..<br/>
        /// </summary>
        public static class TimeStampTypes
        {
            /// <summary>
            /// host-provided, unknown characteristics
            /// </summary>
            public const int PCAP_TSTAMP_HOST = 0;  /*  */

            /// <summary>
            /// host-provided, low precision, synced with the system clock
            /// </summary>
            public const int PCAP_TSTAMP_HOST_LOWPREC = 1;

            /// <summary>
            /// host-provided, high precision, synced with the system clock
            /// </summary>
            public const int PCAP_TSTAMP_HOST_HIPREC = 2;

            /// <summary>
            /// device-provided, synced with the system clock
            /// </summary>
            public const int PCAP_TSTAMP_ADAPTER = 3;

            /// <summary>
            /// device-provided, not synced with the system clock
            /// </summary>
            public const int PCAP_TSTAMP_ADAPTER_UNSYNCED = 4;

            /// <summary>
            /// host-provided, high precision, not synced with the system clock
            /// </summary>
            public const int PCAP_TSTAMP_HOST_HIPREC_UNSYNCED = 5;
        }

        /// <summary>
        /// Time stamp resolution types.<br/>
        /// Not all systems and interfaces will necessarily support all of these<br/>
        /// resolutions when doing live captures; all of them can be requested<br/>
        /// when reading a savefile.<br/>
        /// </summary>
        public static class TimeStampResolutionTypes
        {
            /// <summary>
            /// use timestamps with microsecond precision, default
            /// </summary>
            public const int PCAP_TSTAMP_PRECISION_MICRO = 0;

            /// <summary>
            /// use timestamps with nanosecond precision
            /// </summary>
            public const int PCAP_TSTAMP_PRECISION_NANO = 1;
        }

        public static class WarningCodes
        {
            /// <summary>
            /// generic warning code
            /// </summary>
            public const int PCAP_WARNING = 1;

            /// <summary>
            /// this device doesn't support promiscuous mode
            /// </summary>
            public const int PCAP_WARNING_PROMISC_NOTSUP = 2;

            /// <summary>
            /// the requested time stamp type is not supported
            /// </summary>
            public const int PCAP_WARNING_TSTAMP_TYPE_NOTSUP = 3;
        }

        public static class ErrorCodes
        {
            /// <summary>
            /// generic error code
            /// </summary>
            public const int PCAP_ERROR = -1;
            /// <summary>
            /// loop terminated by pcap_breakloop
            /// </summary>
            public const int PCAP_ERROR_BREAK = -2;
            /// <summary>
            /// the capture needs to be activated
            /// </summary>
            public const int PCAP_ERROR_NOT_ACTIVATED = -3;
            /// <summary>
            /// the operation can't be performed on already activated captures
            /// </summary>
            public const int PCAP_ERROR_ACTIVATED = -4;
            /// <summary>
            /// no such device exists
            /// </summary>
            public const int PCAP_ERROR_NO_SUCH_DEVICE = -5;
            /// <summary>
            /// this device doesn't support rfmon (monitor) mode
            /// </summary>
            public const int PCAP_ERROR_RFMON_NOTSUP = -6;
            /// <summary>
            /// operation supported only in monitor mode
            /// </summary>
            public const int PCAP_ERROR_NOT_RFMON = -7;
            /// <summary>
            /// no permission to open the device
            /// </summary>
            public const int PCAP_ERROR_PERM_DENIED = -8;
            /// <summary>
            /// interface isn't up
            /// </summary>
            public const int PCAP_ERROR_IFACE_NOT_UP = -9;
            /// <summary>
            /// this device doesn't support setting the time stamp type
            /// </summary>
            public const int PCAP_ERROR_CANTSET_TSTAMP_TYPE = -10;
            /// <summary>
            /// you don't have permission to capture in promiscuous mode
            /// </summary>
            public const int PCAP_ERROR_PROMISC_PERM_DENIED = -11;
            /// <summary>
            /// the requested time stamp precision is not supported
            /// </summary>
            public const int PCAP_ERROR_TSTAMP_PRECISION_NOTSUP = -12;
            /// <summary>
            /// capture mechanism not available
            /// </summary>
            public const int PCAP_ERROR_CAPTURE_NOTSUP = -13;
        }
    }
}
