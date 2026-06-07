namespace npcap.net
{
    public enum DumpFileRollingMode
    {
        /// <summary>
        /// Rolls a new dump file when the size limit is reached.
        /// </summary>
        /// 
        RollBySize,

        /// <summary>
        /// Rolls a new dump file every day.
        /// </summary>
        RollDaily
    }
}
