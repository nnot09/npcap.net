using System;
using System.Collections.Generic;
using System.Text;

namespace npcap.net.Exceptions
{
    internal class NpcapNotInstalledException : Exception
    {
        public NpcapNotInstalledException(string message) 
            : base(message)
        {
             
        }
    }
}
