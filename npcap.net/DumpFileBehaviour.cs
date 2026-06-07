namespace npcap.net
{
    public enum DumpFileBehaviour
    {
        /// <summary>
        /// On packet capture, write to the dump file immediately. However, this may cause performance issues.
        /// </summary>
        WritePerPacket,

        /// <summary>
        /// On packet capture, write to the dump file only when the internal capture threshold is reached.
        /// </summary>
        WriteThreshold
    }
}
