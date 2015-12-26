// Shane.Macaulay@IOActive.com Copyright (C) 2013-2015

//Copyright(C) 2015 Shane Macaulay

//This program is free software; you can redistribute it and/or
//modify it under the terms of the GNU General Public License
//as published by the Free Software Foundation.

//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
//GNU General Public License for more details.

//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


using ProtoBuf;
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

            IFormatter formatter = ProtoBuf.Serializer.CreateFormatter<T>();
            using (Stream stream = new MemoryStream())
            {
                formatter.Serialize(stream, source);
                stream.Seek(0, SeekOrigin.Begin);
                return (T)formatter.Deserialize(stream);
            }
        }

        public static T DeepCopy<T>(T objectCopy) where T : new()
        {
            using (var stream = new MemoryStream())
            {
                T rv = new T();
                Serializer.Serialize(stream, rv);
                stream.Position = 0;
                rv = Serializer.Deserialize<T>(stream);
                return rv;
            }

        }
    }
}
