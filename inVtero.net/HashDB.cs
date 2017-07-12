using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ProtoBuf;
using inVtero.net.Hashing;
using System.IO;
using System.IO.MemoryMappedFiles;

namespace inVtero.net
{
    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public class HashDB : IDisposable
    {
        public string HashDBFile;
        public string HashDBBitMap;
        public string RelocFolder;
        public long DBSize;
        public long DBEntries;
        

        public string Reloc64Dir;
        public string Reloc32Dir;

        [ProtoIgnore]
        public MemoryMappedFile BitMap;
        [ProtoIgnore]
        public MemoryMappedViewAccessor BitMapView;
        [ProtoIgnore]
        public UnsafeHelp Bit;

        public HashDB(string DB, string relocFolder, long Size = 0) 
        {
            HashDBFile = DB;
            HashDBBitMap = DB + ".bin";
            if(Size !=0)
                DBSize = (long) FractHashTree.RoundUpPow2(Size);
            RelocFolder = relocFolder;

            Init();
        }

        void Init()
        {
            Reloc64Dir = Path.Combine(RelocFolder, "64");
            Reloc32Dir = Path.Combine(RelocFolder, "32");

            if (!Directory.Exists(Reloc64Dir))
                Directory.CreateDirectory(Reloc64Dir);
            if (!Directory.Exists(Reloc32Dir))
                Directory.CreateDirectory(Reloc32Dir);

            if (!File.Exists(HashDBFile))
            {
                if(!FractHashTree.IsPow2(DBSize))
                    throw new InternalBufferOverflowException($"DB SIZE not a power of 2!");

                using (var fileStream = new FileStream(HashDBFile, FileMode.Create, FileAccess.Write, FileShare.None))
                    fileStream.SetLength(DBSize + 4096);
            } else
                DBSize = (long)FractHashTree.RoundDownPow2(new FileInfo(HashDBFile).Length);
            
            // Divide by 16
            DBEntries = DBSize >> 4;

            // is there a bitmap?
            BitMap = MemoryMappedFile.CreateFromFile(HashDBBitMap, FileMode.OpenOrCreate, "HDBBitMap", DBEntries >> 3);
            BitMapView = BitMap.CreateViewAccessor();

            Bit = new UnsafeHelp();
            Bit.GetBitmapHandle(BitMapView);
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                { }

                if (BitMapView != null && Bit != null)
                {
                    Bit.ReleaseBitmapHandle(BitMapView);
                    Bit = null;
                }
                if (BitMapView != null)
                    BitMapView.Dispose();
                if(BitMap != null)
                    BitMap.Dispose();

                disposedValue = true;
            }
        }

        ~HashDB() {
           // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
           Dispose(false);
         }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            Dispose(true);
        }
        #endregion
    }
}
