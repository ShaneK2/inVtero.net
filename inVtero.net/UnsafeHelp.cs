// Copyright(C) 2017 Shane Macaulay smacaulay@gmail.com
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or(at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.If not, see<http://www.gnu.org/licenses/>.


using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace inVtero.net
{
    public unsafe class UnsafeHelp
    {
        const int WORD_MOD_SIZE = 31;
        const int WORD_BIT_SHIFT = 5; // right shift 5 = /32, 4 = /16

        public static unsafe void ReadBytes(MemoryMappedViewAccessor view, long offset, ref long[] arr, int Count = 512)
        {
            //byte[] arr = new byte[num];
            var ptr = (byte*)0;

            view.SafeMemoryMappedViewHandle.AcquirePointer(ref ptr);
            var ip = new IntPtr(ptr);
            var iplong = ip.ToInt64() + offset;
            var ptr_off = new IntPtr(iplong);

            Marshal.Copy(ptr_off, arr, 0, Count);
            view.SafeMemoryMappedViewHandle.ReleasePointer();
        }

        int* lp = (int *)0;

        public unsafe void GetBitmapHandle(MemoryMappedViewAccessor view)
        {
            var ptr = (byte*)0;
            view.SafeMemoryMappedViewHandle.AcquirePointer(ref ptr);
            lp = (int*)ptr;
        }

        public unsafe void ReleaseBitmapHandle(MemoryMappedViewAccessor view)
        {
            view.SafeMemoryMappedViewHandle.ReleasePointer();
        }

        public unsafe bool GetBit(MemoryMappedViewAccessor view, int bit)
        {
            return (lp[(bit >> WORD_BIT_SHIFT)] & (1 << (bit & WORD_MOD_SIZE))) != 0;

        }
        public unsafe void SetBit(MemoryMappedViewAccessor view, int bit)
        {
            lp[(bit >> WORD_BIT_SHIFT)] |= (1 << (bit & WORD_MOD_SIZE));
        }

        /// <summary>
        /// </summary>
        /// <param name="view"></param>
        /// <param name="ScanFor"></param>
        /// <param name="Count"></param>
        /// <returns></returns>
        public static unsafe List<long> ScanBytes(MemoryMappedViewAccessor view, int ScanFor, int Count = 512)
        {
            var rv = new List<long>();
            var ptr = (byte*)0;

            view.SafeMemoryMappedViewHandle.AcquirePointer(ref ptr);

            var iptr = (int*)ptr;

            for (long i = 0; i < Count; i++)
                if (iptr[i] == ScanFor)
                    rv.Add(i*4);

            view.SafeMemoryMappedViewHandle.ReleasePointer();

            return rv;
        }

        [DllImport("msvcrt.dll", EntryPoint = "memcpy", CallingConvention = CallingConvention.Cdecl, SetLastError = false), SuppressUnmanagedCodeSecurity]
        public static unsafe extern void* CopyMemory(void* dest, void* src, ulong count);


        public static unsafe bool EqualBytesLongUnrolled(long[] data1, long[] data2, int offset = 0, int maxlen = 0)
        {
            if (data1 == data2)
                return true;

            if (data1.Length != data2.Length)
                return false;

            fixed (long* bytes1 = data1, bytes2 = data2)
            {
                var len = 0;

                if (maxlen != 0 && maxlen < (data1.Length - offset))
                    len = maxlen - offset;
                else
                    len = data1.Length - offset;

                int rem = len % (sizeof(long) * 16);
                long* b1 = (long*)bytes1 + offset;
                long* b2 = (long*)bytes2 + offset;
                long* e1 = (long*)(bytes1 + offset + len - rem);

                while (b1 < e1)
                {
                    if (*(b1) != *(b2) || *(b1 + 1) != *(b2 + 1) ||
                        *(b1 + 2) != *(b2 + 2) || *(b1 + 3) != *(b2 + 3) ||
                        *(b1 + 4) != *(b2 + 4) || *(b1 + 5) != *(b2 + 5) ||
                        *(b1 + 6) != *(b2 + 6) || *(b1 + 7) != *(b2 + 7) ||
                        *(b1 + 8) != *(b2 + 8) || *(b1 + 9) != *(b2 + 9) ||
                        *(b1 + 10) != *(b2 + 10) || *(b1 + 11) != *(b2 + 11) ||
                        *(b1 + 12) != *(b2 + 12) || *(b1 + 13) != *(b2 + 13) ||
                        *(b1 + 14) != *(b2 + 14) || *(b1 + 15) != *(b2 + 15))
                        return false;
                    b1 += 16;
                    b2 += 16;
                }

                for (int i = 0; i < rem; i++)
                    if (data1[len - 1 - i] != data2[len - 1 - i])
                        return false;

                return true;
            }
        }
        public static unsafe bool IsZero(long[] data, int offset = 0, int count = 512)
        {
            fixed (long* bytes = data)
            {
                int rem = count % (sizeof(long) * 16);
                long* b = (long*)bytes + offset;
                long* e = (long*)(bytes + count - rem);

                while (b < e)
                {
                    if ((*(b) | *(b + 1) | *(b + 2) | *(b + 3) | *(b + 4) |
                        *(b + 5) | *(b + 6) | *(b + 7) | *(b + 8) |
                        *(b + 9) | *(b + 10) | *(b + 11) | *(b + 12) |
                        *(b + 13) | *(b + 14) | *(b + 15)) != 0)
                        return false;
                    b += 16;
                }

                for (int i = 0; i < rem; i++)
                    if (data[count - 1 - i] != 0)
                        return false;

                return true;
            }
        }
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        private const uint FILE_READ_EA = 0x0008;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x2000000;

        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern uint GetFinalPathNameByHandle(IntPtr hFile, [MarshalAs(UnmanagedType.LPTStr)] StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CreateFile(
                [MarshalAs(UnmanagedType.LPTStr)] string filename,
                [MarshalAs(UnmanagedType.U4)] uint access,
                [MarshalAs(UnmanagedType.U4)] FileShare share,
                IntPtr securityAttributes, // optional SECURITY_ATTRIBUTES struct or IntPtr.Zero
                [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition,
                [MarshalAs(UnmanagedType.U4)] uint flagsAndAttributes,
                IntPtr templateFile);

        public static string GetFinalPathName(string path)
        {
            var h = CreateFile(path,
                FILE_READ_EA,
                FileShare.ReadWrite | FileShare.Delete,
                IntPtr.Zero,
                FileMode.Open,
                FILE_FLAG_BACKUP_SEMANTICS,
                IntPtr.Zero);
            if (h == INVALID_HANDLE_VALUE)
                throw new Win32Exception();

            try
            {
                var sb = new StringBuilder(1024);
                var res = GetFinalPathNameByHandle(h, sb, 1024, 0);
                if (res == 0)
                    throw new Win32Exception();

                return sb.ToString();
            }
            finally
            {
                CloseHandle(h);
            }
        }
    }
}
