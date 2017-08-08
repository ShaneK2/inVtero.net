using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace inVtero.net.Hashing
{
    public class CloudBitmapDB
    {
        // after all that work with Roaring CLI 
        // serverless azure will not support my 64bit stuff :(
        // emulate with 2 32bit DB's for now

        RoaringBitmap high;
        RoaringBitmap low;

        public CloudBitmapDB(string aPath)
        {
            string highPath = $"{aPath}.high.bin";
            string lowPath = $"{aPath}.low.bin";

            if (File.Exists(highPath))
                high = RoaringBitmap.Deserialize(File.ReadAllBytes(highPath), SerializationFormat.Portable);
            else
                high = new RoaringBitmap();

            if (File.Exists(lowPath))
                low = RoaringBitmap.Deserialize(File.ReadAllBytes(lowPath), SerializationFormat.Portable);
            else
                low = new RoaringBitmap();
        }

        public void Set(ulong bit)
        {
            high.Add((uint) (bit >> 32));
            low.Add((uint) bit & uint.MaxValue);
        }

        public void Save(string aPath)
        {
            File.WriteAllBytes($"{aPath}.high.bin", high.Serialize(SerializationFormat.Portable));
            File.WriteAllBytes($"{aPath}.low.bin", low.Serialize(SerializationFormat.Portable));
        }
    }
}
