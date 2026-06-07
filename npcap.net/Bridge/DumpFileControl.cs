using System;
using System.Collections.Generic;
using System.Runtime.InteropServices.Marshalling;
using System.Text;

namespace npcap.net.Bridge
{
    public class DumpFileControl : IDisposable
    {
        private readonly Npcap _npcap;

        public DumpFileControl(Npcap npcap)
        {
            _npcap = npcap;
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}
