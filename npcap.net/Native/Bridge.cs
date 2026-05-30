using npcap.net.Exceptions;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace npcap.net.Native
{
    internal class Bridge
    {
        public static IntPtr LoadLibrary(string dllPath)
        {
            if (dllPath.IsNullOrWhiteSpace())
            {
                throw new ArgumentException("DLL path cannot be null or whitespace.", nameof(dllPath));
            }

            if (!File.Exists(dllPath))
            {
                throw new FileNotFoundException($"DLL not found: {dllPath}", dllPath);
            }

            IntPtr handle = IntPtr.Zero;
            try
            {
                handle = NativeLibrary.Load(dllPath);
                if (handle == IntPtr.Zero)
                {
                    throw new DllLoadingFailedException($"Failed to load library: {dllPath} ({Marshal.GetLastWin32Error()})");
                }
            }
            catch (BadImageFormatException ex)
            {
                throw new BadImageFormatException($"Failed to load library (bad image format, probably architecture mismatch): {dllPath}", ex);
            }

            return handle;
        }

        public static void FreeLibrary(IntPtr handle)
        {
            if (handle == IntPtr.Zero)
            {
                throw new ArgumentException("Handle cannot be zero.", nameof(handle));
            }

            if (handle == new IntPtr(-1))
            {
                throw new ArgumentException("Invalid handle, cannot free library.", nameof(handle));
            }

            NativeLibrary.Free((nint)handle);
        }

        public static IntPtr GetExportedFunction(IntPtr libraryHandle, string functionName)
        {
            if (libraryHandle == IntPtr.Zero)
            {
                throw new ArgumentException("Library handle cannot be zero.", nameof(libraryHandle));
            }

            if (libraryHandle == new IntPtr(-1))
            {
                throw new ArgumentException("Invalid library handle.", nameof(libraryHandle));
            }

            if (functionName.IsNullOrWhiteSpace())
            {
                throw new ArgumentException("Function name cannot be empty.", nameof(functionName));
            }

            var functionPtr = NativeLibrary.GetExport(libraryHandle, functionName);
            if (functionPtr == IntPtr.Zero)
            {
                throw new DllLoadingFailedException($"Failed to get exported function: {functionName} ({Marshal.GetLastWin32Error()})");
            }

            return functionPtr;
        }
    }
}
