namespace npcap.net
{
    public enum MinimumLoggingLevel
    {
        /// <summary>
        /// No logs.
        /// </summary>
        None,

        /// <summary>
        /// Debug logs and above (Warning, Error).
        /// </summary>
        Debug,

        /// <summary>
        /// Warning logs and above (Error).
        /// </summary>
        Warning,

        /// <summary>
        /// Only error logs.
        /// </summary>
        Error,

        /// <summary>
        /// All logs.
        /// </summary>
        Full
    }
}
