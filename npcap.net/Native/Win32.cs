using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace npcap.net.Native
{
    // Credits: https://www.pinvoke.net
    internal static class Win32
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hReservedNull, Defs.LoadLibraryFlags dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FreeLibrary(IntPtr hModule);
    }
}
