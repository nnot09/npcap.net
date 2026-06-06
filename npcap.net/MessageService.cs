using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;
using System.Threading.Channels;

namespace npcap.net
{
    internal static class MessageService
    {
        private static Channel<string> _channel;
        private static Task _consumer;
        private static CancellationTokenSource _cts;

        static MessageService()
        {
            _channel = Channel.CreateBounded<string>(new BoundedChannelOptions(512)
            {
                SingleReader = true,
                SingleWriter = false,
                FullMode = BoundedChannelFullMode.DropOldest
            });

            _cts = new CancellationTokenSource();
            _consumer = Task.Run(() => ConsumeAsync());
        }

        public static void Queue(string message)
        {
            _channel.Writer.TryWrite(message);
        }

        private static async Task ConsumeAsync()
        {
            try
            {
                while (await _channel.Reader.WaitToReadAsync(_cts.Token))
                {
                    while (_channel.Reader.TryRead(out var message))
                    {
                        Console.WriteLine(message);
                    }   
                }
            }
            catch (OperationCanceledException) {  }
        }
        
        //public static void Dispose()
        //{
        //    _channel.Writer.Complete();
        //    _consumer.GetAwaiter().GetResult();
        //    _cts.Dispose();
        //}
    }
}
