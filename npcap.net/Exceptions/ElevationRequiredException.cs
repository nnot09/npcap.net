using System;
using System.Collections.Generic;
using System.Text;

namespace npcap.net.Exceptions
{
    internal class ElevationRequiredException : Exception
    {
        public ElevationRequiredException(string message) 
            : base(message)
        {

        }
    }
}
