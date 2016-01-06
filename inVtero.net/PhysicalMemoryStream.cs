using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace inVtero.net
{

    /// <summary>
    /// Stream overlaid the block interface of Mem
    /// </summary>
    class PhysicalMemoryStream : Stream, IDisposable
    {
        DetectedProc Proc;
        Mem MemBlockStorage;
        long position;
        HARDWARE_ADDRESS_ENTRY CurrPage;

        public PhysicalMemoryStream() { position = 0; }

        public PhysicalMemoryStream(Mem blockStorage, DetectedProc proc)
        {
            MemBlockStorage = blockStorage;
            Proc = proc;
        }

        public override long Position
        {
            get { return position; }
            set { position = value; Seek(value, SeekOrigin.Begin); }
        }

        public unsafe override int Read(byte[] buffer, int offset, int count)
        {
            int CurrOff = 0;
            // figure out how many pages we need 
            int PageCount = count / 4096;
            if ((count & 0xfff) != 0)
                PageCount++;

            int rv = PageCount;

            if(offset != 0)
                throw new NotImplementedException("Sub-Page reads not supported");

            while (PageCount > 0)
            {
                // block may be set to null by the GetPageForPhysAddr call, so we need to remake it every time through...
                var lblock = new long[0x200]; // 0x200 * 8 = 4k
                PageCount--;

                fixed (void* lp = lblock, bp = buffer)
                {
                    try {
                        if (MemBlockStorage.GetPageForPhysAddr(CurrPage.PTE, ref lblock) == MagicNumbers.BAD_VALUE_READ)
                            continue;

                        Buffer.MemoryCopy((byte*)lp + CurrOff, (byte*)bp + CurrOff, 4096, 4096);
                    } finally
                    {
                        CurrOff += 0x1000;
                    }
                    
                }
            }

            return (rv - PageCount) * 0x1000;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            HARDWARE_ADDRESS_ENTRY PhysAddr = HARDWARE_ADDRESS_ENTRY.MaxAddr;

            long DestAddr = long.MaxValue;
            switch(origin)
            {
                default:
                case SeekOrigin.Begin:
                    DestAddr = offset;
                    break;
                case SeekOrigin.End:
                    DestAddr = Length - offset;
                    break;
                case SeekOrigin.Current:
                    DestAddr = position;
                    DestAddr += offset;
                    break;
            }

            PhysAddr = MemBlockStorage.VirtualToPhysical(Proc.vmcs.EPTP, Proc.CR3Value, DestAddr);
            if(PhysAddr == HARDWARE_ADDRESS_ENTRY.MinAddr || PhysAddr == HARDWARE_ADDRESS_ENTRY.MaxAddr || PhysAddr == HARDWARE_ADDRESS_ENTRY.MaxAddr-1)
                throw new PageNotFoundException($"unable to locate the physical page for the supplied virtual address {DestAddr}", PhysAddr, null, null);

            position = DestAddr;
            CurrPage = PhysAddr;
            return DestAddr;

        }

        public override bool CanRead { get { return true; } }

        public override bool CanSeek { get { return true; } }

        public override bool CanWrite { get { return false; } }

        public override long Length { get { return MemBlockStorage.Length; } }


        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        private bool disposedValue = false;
        public new virtual void Dispose(bool Disposing)
        {
            if (!disposedValue)
            {
                if (Disposing)
                    MemBlockStorage.Dispose();

                disposedValue = true;
            }
        }

        public new void Dispose()
        {
            Dispose(true);
        }

        ~PhysicalMemoryStream()
        {
            Dispose();
            GC.SuppressFinalize(this);
        }

        public override void Close()
        {
            Dispose();
        }

    }
}
