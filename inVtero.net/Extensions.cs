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
using System.IO;
using System.Linq;
using System.Runtime.Serialization;

namespace inVtero.net
{
    public static class Extensions
    {
        public static IEnumerable<T> IntersectMany<T>(this IEnumerable<IEnumerable<T>> sets) where T : IComparable
        {
            var temp = new HashSet<T>(sets.ElementAt(0));
            sets.ToList().ForEach(z => temp = new HashSet<T>(z.Intersect(temp)));
            return temp;
        }

        public static int SearchBytes(this byte[] haystack, byte[] needle, int startPos = 0, int alignCount = 1)
        {
            var len = needle.Length;
            var limit = haystack.Length - len;
            for (var i = startPos; i <= limit; i += alignCount)
            {
                var k = 0;
                for (; k < len; k++)
                {
                    if (needle[k] != haystack[i + k]) break;
                }
                if (k == len) return i;
            }
            return -1;
        }

        /*  Sort of a waste of memory anyhow, reworked algorithm so this is not needed.


        public static T Clone<T>(this T source)
        {
            if (Attribute.GetCustomAttribute(typeof(T), typeof(ProtoBuf.ProtoContractAttribute))
                   == null)
            {
                throw new ArgumentException("Type has no ProtoContract!", "source");
            }

            if (Object.ReferenceEquals(source, null))
            {
                return default(T);
            }
            //NetSerializer.Serializer
            //IFormatter formatter = ProtoBuf.Serializer.CreateFormatter<T>();
            using (Stream stream = new MemoryStream())
            {
                formatter.Serialize(stream, source);
                stream.Seek(0, SeekOrigin.Begin);
                return (T)formatter.Deserialize(stream);
            }
        }

        */
    }
}
