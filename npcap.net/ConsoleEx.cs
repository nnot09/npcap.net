using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;

namespace npcap.net
{
    internal static class ConsoleEx
    {
        private static void InternalWriteLine(string message, string type = "UNK", string? memberName = null)
        {
            string producerMessage = string.Empty;

            if (memberName == null)
            {
                producerMessage = $"{DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss.fff")} npcap.net [{type}]: {message}";
            }
            else
            {
                producerMessage = $"{DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss.fff")} npcap.net [{type}][{memberName}]: {message}";
            }

            MessageService.Queue(producerMessage);
        }

        public static void Debug(string message, [CallerMemberName] string? memberName = null)
        {
            if (!Global.ShouldLogDebug) return;
            InternalWriteLine(message, "INF", memberName);
        }

        public static void Warning(string message, [CallerMemberName] string? memberName = null)
        {
            if (!Global.ShouldLogWarning) return;
            InternalWriteLine(message, "WRN", memberName);
        }

        public static void Error(string message, [CallerMemberName] string? memberName = null)
        {
            if (!Global.ShouldLogError)
            InternalWriteLine(message, "ERR", memberName);
        }
    }
}
