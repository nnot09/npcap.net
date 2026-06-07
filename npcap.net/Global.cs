using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

[assembly: InternalsVisibleTo("npcap.net.Tests")]

namespace npcap.net
{
    internal static class Global
    {
        public static bool ShouldLogDebug { get; private set; }
        public static bool ShouldLogWarning { get; private set; }
        public static bool ShouldLogError { get; private set; }
        public static bool ShouldLogFull { get; private set; }

        public static void InitializeLoggingLevels(MinimumLoggingLevel minimumLoggingLevel)
        {
            if (minimumLoggingLevel == MinimumLoggingLevel.None)
            {
                ShouldLogDebug = false;
                ShouldLogWarning = false;
                ShouldLogError = false;
                ShouldLogFull = false;
                return;
            }

            if (minimumLoggingLevel == MinimumLoggingLevel.Full || minimumLoggingLevel == MinimumLoggingLevel.Debug)
            {
                ShouldLogDebug = true;
                ShouldLogWarning = true;
                ShouldLogError = true;
                ShouldLogFull = true;
                return;
            }

            ShouldLogDebug = false;
            ShouldLogFull = false;
            ShouldLogWarning = minimumLoggingLevel <= MinimumLoggingLevel.Warning;
            ShouldLogError = minimumLoggingLevel <= MinimumLoggingLevel.Error;
        }
    }
}
