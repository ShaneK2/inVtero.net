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
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Threading;
using static inVtero.net.Misc;

namespace inVtero.net
{
    public static class Extensions
    {
        public static Func<T, U> WithRetries<T, U>(this Func<T, U> func, int intervalInMilliseconds, int maxAttempts, string message)
        {
            U InnerFunc(T Arg)
            {
                // ensure at least one attempt is made
                if (maxAttempts <= 0) maxAttempts = 1;
                var success = false;
                var attempts = 0;
                var result = default(U);

                while (!success && attempts < maxAttempts)
                {
                    attempts++;
                    try
                    {
                        if (Vtero.VerboseLevel > 3)
                            WriteColor(ConsoleColor.White, $"In WithRetries for {message}; attempt number {attempts} of {maxAttempts} maximum attempts.");
                        result = func(Arg);
                        success = true;
                    }
                    catch (Exception ex)
                    {
                        var errMsg = $"Retry attempt {attempts} experienced the following exception: {ex.Message} | ";
                        if (Vtero.VerboseLevel > 1)
                            WriteColor(ConsoleColor.Yellow, errMsg);

                        if (attempts >= maxAttempts)
                        {
                            errMsg += $"{message} Maximum retry count of {maxAttempts} with an interval of {intervalInMilliseconds} milliseconds was met. {ex.Message}";

                            WriteColor(ConsoleColor.Red, errMsg);

                            throw new Exception(errMsg);
                        }
                        Thread.Sleep(intervalInMilliseconds);
                    }
                }
                return result;
            }
            return (inputArg) => InnerFunc(inputArg);
        }

        static ExpandoObject ShallowCopy(ExpandoObject original)
        {
            var clone = new ExpandoObject();

            var _original = (IDictionary<string, object>)original;
            var _clone = (IDictionary<string, object>)clone;

            foreach (var kvp in _original)
                _clone.Add(kvp);

            return clone;
        }

        public static ExpandoObject DeepCopy(this ExpandoObject original)
        {
            var clone = new ExpandoObject();

            var _original = (IDictionary<string, object>)original;
            var _clone = (IDictionary<string, object>)clone;

            foreach (var kvp in _original)
                _clone.Add(kvp.Key, kvp.Value is ExpandoObject ? DeepCopy((ExpandoObject)kvp.Value) : kvp.Value);

            return clone;
        }

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
        public static int SearchLong(this long[] haystack, long[] needle, int startPos = 0, int alignCount = 1)
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
