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

        public override int Read(byte[] buffer, int offset, int count)
        {
            bool GoodRead = false;
            int CurrOff = 0;
            // figure out how many pages we need 
            int PageCount = count / MagicNumbers.PAGE_SIZE;
            if ((count & 0xfff) != 0)
                PageCount++;

            int rv = PageCount;

            if(offset != 0)
                throw new NotImplementedException("Sub-Page reads not supported, use BufferedStream to even out your access pattern.");

            var lblock = new long[0x200]; // 0x200 * 8 = 4k
            while (PageCount > 0)
            {
                PageCount--;

                MemBlockStorage.GetPageForPhysAddr(CurrPage.PTE, ref lblock, ref GoodRead);
                if (!GoodRead)
                    continue;

                Buffer.BlockCopy(lblock, CurrOff/4, buffer, CurrOff, MagicNumbers.PAGE_SIZE);
                CurrOff += MagicNumbers.PAGE_SIZE;
            }

            return (rv - PageCount) * MagicNumbers.PAGE_SIZE;
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

        /// <summary>
        /// This should be the length of the VA space for the given Proc that were looking at
        /// </summary>
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
