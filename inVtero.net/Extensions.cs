using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
    }
}
