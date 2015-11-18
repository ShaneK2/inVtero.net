using System;
using System.Collections.Generic;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace inVtero.net
{
    public class UnsafeHelp
    {

        public static unsafe void ReadBytes(MemoryMappedViewAccessor view, long offset, ref long[] arr)
        {
            //byte[] arr = new byte[num];
            var ptr = (byte*)0;

            view.SafeMemoryMappedViewHandle.AcquirePointer(ref ptr);
            var ip = new IntPtr(ptr);
            var iplong = ip.ToInt64() + offset;
            var ptr_off = new IntPtr(iplong);

            Marshal.Copy(ptr_off, arr, 0, 512);
            view.SafeMemoryMappedViewHandle.ReleasePointer();
        }

        [DllImport("msvcrt.dll", EntryPoint = "memcpy", CallingConvention = CallingConvention.Cdecl, SetLastError = false), SuppressUnmanagedCodeSecurity]
        public static unsafe extern void* CopyMemory(void* dest, void* src, ulong count);


        public static unsafe bool EqualBytesLongUnrolled(long[] data1, long[] data2, int maxlen = 0)
        {
            if (data1 == data2)
                return true;
            if (data1.Length != data2.Length)
                return false;

            fixed (long* bytes1 = data1, bytes2 = data2)
            {
                int len = 0;

                if (maxlen != 0 && maxlen < data1.Length)
                    len = maxlen;
                else
                    len = data1.Length;

                int rem = len % (sizeof(long) * 16);
                long* b1 = (long*)bytes1;
                long* b2 = (long*)bytes2;
                long* e1 = (long*)(bytes1 + len - rem);

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
        public static unsafe bool IsZero(long[] data)
        {
            fixed (long* bytes = data)
            {
                int len = data.Length;
                int rem = len % (sizeof(long) * 16);
                long* b = (long*)bytes;
                long* e = (long*)(bytes + len - rem);

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
                    if (data[len - 1 - i] != 0)
                        return false;

                return true;
            }
        }
    }
}
