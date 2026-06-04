using System;
using System.Collections.Generic;
using System.Text;

namespace npcap.net.Types
{
    public class Library
    {
        public required string Name { get; set; }
        public required string Path { get; set; }
        public required IntPtr Handle { get; set; }
    }
}
