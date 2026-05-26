using System;
using System.Collections.Generic;
using System.Text;

namespace npcap.net.NewFolder
{
    internal class DllLoadingFailedException : Exception
    {
        public DllLoadingFailedException(string message)
            : base(message)
        {
             
        }
    }
}
