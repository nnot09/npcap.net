using Microsoft.Win32;
using npcap.net.ManagedTypes;
using npcap.net.Native;
using System;
using System.Collections.Generic;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Channels;
using static npcap.net.Native.WpcapStructs;

namespace npcap.net
{
    internal static class Helpers
    {
        public static (bool IsTrue, string? Reason) IsElevated()
        {
            if (!OperatingSystem.IsWindows())
            {
                return (false, "This library requires Windows OS.");
            }
            
            if (RuntimeInformation.ProcessArchitecture != Architecture.X64)
            {
                return (false, "This library requires x64.");
            }

            var current = WindowsIdentity.GetCurrent();
            if (ReferenceEquals(current, null))
            {
                return (false, "Current identity is null.");
            }

            var isElevated = new WindowsPrincipal(current).IsInRole(WindowsBuiltInRole.Administrator);
            if (isElevated)
            {
                return (true, null);
            }
            else
            {
                return (false, "This library requires administrative privileges to run.");
            }
        }

        public static bool IsNpcapInstalled()
        {
            // "C:\Program Files\Npcap\CheckStatus.bat"

#pragma warning disable CA1416 // Validate platform compatibility
            RegistryKey? key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\WOW6432Node\\Npcap");
            if (ReferenceEquals(key, null))
            {
                return false;
            }

            var value = key.GetValue(null);
            if (value == null)
            {
                return false;
            }

            var path = value.ToString();
            if (path.IsNullOrWhiteSpace())
            {
                return false;
            }

            string npcapFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Npcap");
            if (!Directory.Exists(npcapFolder))
            {
                return false;
            }

            return Directory.Exists(path);
#pragma warning restore CA1416 // Validate platform compatibility
        }

        public static List<TStruct> ConvertIntPtrLinkedListToManagedList<TStruct>(this IntPtr ptr)
            where TStruct : struct, ILinkedList
        {
            if (ptr == IntPtr.Zero)
            {
                return new List<TStruct>();
            }

            List<TStruct> ret = new List<TStruct>();
            unsafe
            {
                IntPtr current = ptr;

                while (current != IntPtr.Zero)
                {
                    TStruct testttr = Marshal.PtrToStructure<TStruct>(current);
                    ret.Add(testttr);
                    current = (IntPtr)((ILinkedList)testttr).next;
                }
            }

            return ret;
        }

        public static bool IsNullOrWhiteSpace(this string? value) => string.IsNullOrWhiteSpace(value);
    }
}
