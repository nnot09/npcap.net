using System;
using System.Collections.Generic;
using System.Text;

namespace npcap.net
{
    public class NpcapOptions
    {
        public bool EnablePacketPrinting { get; set; }
        public bool CreateDumpFile { get; set; }
        public string? OutputDirectory { get; set; }
        public DumpFileBehaviour DumpFileBehaviour { get; set; }
        public DumpFileRollingMode DumpFileRollingMode { get; set; }
        public long? DumpFileInternalPacketBufferSizeThreshold { get; set; }
        public long? DumpFileSizeThreshold { get; set; }
        public SizeUnit DumpFilePacketSizeThresholdUnit { get; set; }
        public SizeUnit DumpFileRollingSizeThreshold { get; set; }

        public NpcapOptions Default => new NpcapOptions()
        {
            CreateDumpFile = true,
            EnablePacketPrinting = false,
            OutputDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "npcap.net"),
            DumpFileBehaviour = DumpFileBehaviour.WriteThreshold,
            DumpFileRollingMode = DumpFileRollingMode.RollBySize,
            DumpFileInternalPacketBufferSizeThreshold = 1024,
            DumpFilePacketSizeThresholdUnit = SizeUnit.KiB,
            DumpFileSizeThreshold = 512,
            DumpFileRollingSizeThreshold = SizeUnit.MiB
        };
    }
}
