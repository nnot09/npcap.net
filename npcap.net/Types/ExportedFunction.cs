using System;
using System.Collections.Generic;
using System.Text;

namespace npcap.net.Types
{
    internal class ExportedFunction
    {
        public required string Name { get; set; }
        public required IntPtr Address { get; set; }
    }
}
