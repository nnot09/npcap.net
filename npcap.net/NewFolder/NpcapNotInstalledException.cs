using System;
using System.Collections.Generic;
using System.Text;

namespace npcap.net.NewFolder
{
    internal class NpcapNotInstalledException : Exception
    {
        public NpcapNotInstalledException(string message) 
            : base(message)
        {
             
        }
    }
}
