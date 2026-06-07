using npcap.net.ManagedTypes;
using npcap.net.Native;
using PacketDotNet;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Channels;
using static npcap.net.Native.WpcapStructs;

namespace npcap.net.Bridge
{
    public class CaptureControl
    {
        private readonly Npcap _npcap;

        public CaptureControl(Npcap npcap)
        {
            this._npcap = npcap;
        }

        public bool Capture(Device device, string filter)
        {
            CancellationTokenSource cts = new CancellationTokenSource();

            unsafe
            {
                var bpfFilter = _npcap.Filter.Compile(device, filter);
                if (!_npcap.Filter.SetFilter(device, bpfFilter))
                {
                    return false;
                }

                ConsoleEx.Debug("initializing I/O channels...");

                /*
                 * msdn
                 * "But instead, imagine that you want to create an unbounded channel with multiple producers and consumers. 
                 *  Set SingleWriter = false and SingleReader = false in the channel options"
                 *  default seems to create false/false, allowing multiple producers and consumers
                 *  
                 *  however, unbounded channels are a MISERABLE choice here..consider bounded channels
                 */
                var channel = Channel.CreateUnbounded<RawPacket>(new UnboundedChannelOptions()
                {
                    SingleReader = true,
                    SingleWriter = true
                });

                var producerTask = Task.Run(() => ProducerAsync(device, channel.Writer, cts.Token));
                var consumerTask = Task.Run(() => ConsumerAsync(channel.Reader, cts.Token));

                Task.WhenAll(producerTask, consumerTask).ContinueWith(p =>
                {
                    Wpcap.pcap_freecode(bpfFilter);
                    cts.Dispose();
                    ConsoleEx.Debug($"capture for device '{device.Name}' completed");
                });

                // TODO handle task disposal
                //producerTask.Dispose();
                //consumerTask.Dispose();

                ConsoleEx.Debug($"starting packet capture of device '{device.Name}' using filter: '{filter}'");
                return true;
            }
        }

        private unsafe async Task ProducerAsync(Device device, ChannelWriter<RawPacket> writer, CancellationToken token)
        {
            try
            {
                int reuslt = -1;
                while ((reuslt = Wpcap.pcap_next_ex((WpcapStructs.pcap*)device.Handle, out IntPtr packetHeader, out IntPtr data)) >= 0)
                {
                    if (token.IsCancellationRequested) break;
                    if (reuslt == 0) continue;
                    if (packetHeader == IntPtr.Zero || data == IntPtr.Zero)
                    {
                        ConsoleEx.Warning($"received nullptr from packet header or data");
                        continue;
                    }

                    var hdr = Marshal.PtrToStructure<pcap_pkthdr>(packetHeader);
                    var linktype = Wpcap.pcap_datalink((WpcapStructs.pcap*)device.Handle);
                    var packet = new RawPacket((LinkLayers)linktype, data, hdr.len, hdr.caplen, DateTime.Now);
                    // _npcap.Events.OnPacketCaptured(packet);

                    writer.TryWrite(packet);
                }

                if (reuslt == -1)
                {
                    string err = Wpcap.pcap_geterr(device.Handle);
                    ConsoleEx.Error($"{nameof(Wpcap.pcap_next_ex)} error on '{device.Name}': {err}");
                }
            }
            finally
            {
                writer.Complete();
            }
        }

        private async Task ConsumerAsync(ChannelReader<RawPacket> reader, CancellationToken token)
        {
            try
            {
                while (await reader.WaitToReadAsync(token))
                {
                    while (reader.TryRead(out var rawPacket))
                    {
                        _npcap.Events.OnPacketCaptured(rawPacket);

                        if (_npcap.EnablePacketPrinting)
                        {
                            MessageService.Queue(rawPacket.Packet.ToString());
                        }
                    }
                }

                //await foreach (var packet in reader.ReadAllAsync(token))
                //{
                //    _npcap.Events.OnPacketCaptured(packet);
                //}
            }
            catch (OperationCanceledException) { }
        }
    }
}
