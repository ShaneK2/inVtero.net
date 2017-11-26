using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using static Dia2Sharp.DebugHelp;
using System.Linq;
using System.Collections.Concurrent;
using System.Dynamic;
using System.Threading.Tasks;
using Newtonsoft.Json.Converters;
using System.Text.RegularExpressions;

namespace Dia2Sharp
{
    // not sure this thunk was a great idea, it's a lot easier to clean up the use to just fit our application ;)
    public class DiaSource
    {
        CODEVIEW_HEADER CV;

        public DiaSource()
        {

        }
        public DiaSource(CODEVIEW_HEADER cv) :this()
        {
            CV = cv;
        }

        public void loadDataFromPdb(string pdbPath)
        {
            return;
        }
        public void openSession(out IDiaSession Sess)
        {
            Sess = new DiaSession(CV);
            return;
        }
    }

    public interface IDiaSession
    {
        IDiaSymbol globalScope { get; set; }
        ulong loadAddress { get; set; }
        void findChildren(IDiaSymbol parent, SymTagEnum symTag, string name, uint compareFlags, out IDiaEnumSymbols ppResult);
        void getSymbolsByAddr(out IDiaEnumSymbolsByAddr ppEnumbyAddr);
    }
    public interface IDiaEnumSymbols
    {
        IEnumerator<IDiaSymbol> GetEnumerator();
        IDiaSymbol Item(uint index);
        void Next(uint celt, out IDiaSymbol rgelt, out uint pceltFetched);
        void Skip(uint celt);
        void Reset();
        void Clone(out IDiaEnumSymbols ppenum);

        int count { get; }
    }
    public interface IDiaEnumSymbolsByAddr
    {
        IDiaSymbol symbolByVA(ulong virtualAddress);
    }

    public interface IDiaSymbol
    {
        IDiaSymbol type { get; }
        string name { get; }
        ulong length { get; }
        ulong virtualAddress { get; }
        uint locationType { get; }
        dynamic value { get; }
        int offset { get; }
        uint symTag { get; }
        uint bitPosition { get; }

        void findChildren(SymTagEnum symTag, string name, uint compareFlags, out IDiaEnumSymbols ppResult);
    }

    public class JsonSymbol : IDiaSymbol
    {
        dynamic Info;

        public JsonSymbol(dynamic info)
        {
            Info = info;
        }

        // query struct from memory cache
        //public IDiaSymbol type => new JsonSymbol(Info.InstanceName);

        public string name => (Info.MemberName as string).Substring((Info.MemberName as string).LastIndexOf('.')+1);

        public ulong length => Info.Length;

        public ulong virtualAddress => Info.vAddress;

        public uint locationType => (uint) (Info.BitCount != 0 ? 6 : (Info.ConstValue != null ? 0xa : 0));

        public ulong ConstValue => Info.ConstValue;

        public dynamic value => Info.Value;

        public int offset => Info.OffsetPos;

        public uint symTag => Info.tag;

        public uint bitPosition => Info.BitPosition;

        public uint bitCount => Info.BitCount;

        public IDiaSymbol type => null;

        public void findChildren(SymTagEnum symTag, string name, uint compareFlags, out IDiaEnumSymbols ppResult)
        {
            throw new NotImplementedException();
        }
    }

    // TODO: Enumerator cache
    public class DiaSession : IDiaSession
    {
        CODEVIEW_HEADER CV;

        public DiaSession() { }
        public DiaSession(CODEVIEW_HEADER cv)
        {
            CV = cv;
        }

        public IDiaSymbol globalScope { get; set; }
        public ulong loadAddress { get; set; }

        void IDiaSession.findChildren(IDiaSymbol parent, SymTagEnum symTag, string name, uint compareFlags, out IDiaEnumSymbols ppResult)
        {
            dynamic typ = null;

            if (!Dia3.StructCache.ContainsKey(name))
            {
                var json = SymAPI.TypeDef(name, CV);
                var converter = new Newtonsoft.Json.Converters.ExpandoObjectConverter();
                var obj = JsonConvert.DeserializeObject<List<ExpandoObject>>(json.Result, converter);
                // we access just the first object back
                Dia3.StructCache.TryAdd(name, obj.First());
            }
            Dia3.StructCache.TryGetValue(name, out typ);

            ppResult = new EnumSymbols(CV, EnumSymType.Sym, typ);
            return;
        }
        void IDiaSession.getSymbolsByAddr(out IDiaEnumSymbolsByAddr ppEnumbyAddr)
        {
            dynamic typ = null;

            if (!Dia3.StructCache.ContainsKey(loadAddress.ToString("x")))
            {
                var json = SymAPI.FromAddress(loadAddress.ToString("x"), CV);
                typ = JsonConvert.DeserializeObject<SymNameInfo>(json.Result);

                Dia3.StructCache.TryAdd(loadAddress.ToString("x"), typ);
            }
            Dia3.StructCache.TryGetValue(loadAddress.ToString("x"), out typ);

            ppEnumbyAddr = new EnumSymbols(CV, EnumSymType.ByAddr, typ);
            return;
        }
    }
    public enum EnumSymType
    {
        None = 0,
        Sym = 1,
        ByAddr = 2
    }
    public class EnumSymbols : IDiaEnumSymbols, IDiaEnumSymbolsByAddr
    {
        CODEVIEW_HEADER CV;
        EnumSymType eType;
        dynamic Master;
        IDictionary<string, object> IMaster;
        int curr = 0;

        public IDiaSymbol Current;

        public EnumSymbols() { }
        public EnumSymbols(CODEVIEW_HEADER cv, EnumSymType e, dynamic master)
        {
            CV = cv;
            eType = e;
            Master = master;
            IMaster = master as IDictionary<string, object>;
            count = IMaster.Keys.Count;
        }

        public int count { get; private set; }

        public void Clone(out IDiaEnumSymbols ppenum)
        {
            ppenum = new EnumSymbols(CV, eType, Current) as IDiaEnumSymbols;
            return;
        }

        public IEnumerator<IDiaSymbol> GetEnumerator()
        {
            return new EnumSymbols(CV, eType, Current) as IEnumerator<IDiaSymbol>;
        }

        public IDiaSymbol Item(uint index)
        {
            return null;
        }

        public void MoveNext()
        {
            //Current = IMaster.Keys.ElementAt(curr);
        }

        public void Next(uint celt, out IDiaSymbol rgelt, out uint pceltFetched)
        {
            pceltFetched = 0;
            rgelt = null;
            return;
        }

        public void Reset()
        {
            return;
        }

        public void Skip(uint celt)
        {
            return;
        }

        public IDiaSymbol symbolByVA(ulong virtualAddress)
        {
            return null;
        }
    }

    public class DiaSymbol : IDiaSymbol
    {
        CODEVIEW_HEADER CV;
        public static DiaSymbol GlobalScope;
        dynamic Master;

        public DiaSymbol()
        {
            GlobalScope = new DiaSymbol();
            GlobalScope.name = "";
            GlobalScope.length = ulong.MaxValue;
        }
        public DiaSymbol(CODEVIEW_HEADER cv):this()
        {
            CV = cv;
        }

        public uint bitPosition { get; private set; }
        public uint symTag { get; private set; }
        public int offset { get; private set; }
        public dynamic value { get; private set; }
        public uint locationType { get; private set; }
        public IDiaSymbol type { get; private set; }
        public string name { get; private set; }
        public ulong length { get; private set; }
        public ulong virtualAddress { get; private set; }

        void IDiaSymbol.findChildren(SymTagEnum symTag, string name, uint compareFlags, out IDiaEnumSymbols ppResult)
        {
            ppResult = new EnumSymbols(CV, EnumSymType.Sym, Master);
            return;
        }
    }

    /// <summary>
    /// Manage local symbol cache
    /// </summary>
    public class Dia3 
    {
        CODEVIEW_HEADER CV;
        public static ConcurrentDictionary<string, dynamic> StructCache = new ConcurrentDictionary<string, dynamic>();


        // where the bindings all get originated
        public Dia3(CODEVIEW_HEADER cvh)
        {
            CV = cvh;
        }

        // call web/JSON to get symbols
        public DiaSource OpenSource()
        {
            var rv = new DiaSource(CV);


            return rv;
        }

        // TODO: name->Sym cache

        
    }

    public class NameList { public List<SymNameInfo> Names; }
    public class SymNameInfo { public string Name { get; set; } public ulong Address { get; set; } public ulong Length { get; set; } }



    /// <summary>
    /// 2 layers of caching.
    /// Layer 1 is a webcache so we don't make the same web-request repeatadly expecting different results.
    /// Layer 2 is an ExpandoObject cache since we will need to frequently get a clean instance of our datastructures.
    /// It's infinatly faster to do a DeepCopy than to simply rely on the Newtonsoft deserializer (very slow in comparison)
    /// </summary>
    public static class SymAPI
    {
        public static SYMBOL_INFO SymFromName(string name, CODEVIEW_HEADER cvh)
        {
            SYMBOL_INFO rv = new SYMBOL_INFO();

            var json = SymAPI.FromName(name, cvh);
            var names = JsonConvert.DeserializeObject<NameList>(json.Result);
            if (names == null)
                return rv;

            var first = names.Names.First();

            rv.Address = first.Address;
            rv.Size = (uint)first.Length;
            rv.Name = first.Name;

            return rv;
        }

        /// <summary>
        /// Get a defined type from the symbol API (e.g. _EPROCESS)
        /// After the first call this is all cached staticlly
        /// 
        /// WARNING!!! This means you need to reload every memory dump you're looking at
        /// TODO: Make this instance specific per-vtero
        /// </summary>
        /// <param name="TypeName"></param>
        /// <param name="cv"></param>
        /// <returns></returns>
        public static dynamic GetType(string TypeName, CODEVIEW_HEADER cv = null)
        {
            if (_dyn_cache.TryGetValue(TypeName, out Tuple<String, ExpandoObject> cachedVersion)) return cachedVersion.Item2.DeepCopy();

            var json = TypeDef(TypeName, cv);
            var dyn = JsonConvert.DeserializeObject<List<ExpandoObject>>(json.Result, converter).First();

            _dyn_cache.TryAdd(TypeName, Tuple.Create(json.Result, dyn));

            return dyn.DeepCopy();
        }
        public static string GetTypeString(string TypeName, CODEVIEW_HEADER cv = null)
        {
            if (_dyn_cache.TryGetValue(TypeName, out Tuple<String, ExpandoObject> cachedVersion)) return cachedVersion.Item1;

            return TypeDef(TypeName, cv).Result;
        }

        /// <summary>
        /// Origionally this tended to be a lot faster than dynamically parsing this out of expando's 
        /// </summary>
        /// <param name="TypeName">_EPROCESS or something that is contained by the passed in CV or is cached</param>
        /// <param name="cv">required for first time for a given type</param>
        /// <returns>Dictionary that represents length and offset_of for all defined struct fields (except bitfields)</returns>
        public static Dictionary<string, Tuple<int, int>> GetTypeOffsets(string TypeName, CODEVIEW_HEADER cv = null)
        {
            Dictionary<string, Tuple<int, int>> rv = new Dictionary<string, Tuple<int, int>>();
            var str = GetTypeString(TypeName, cv);

            JsonTextReader reader = new JsonTextReader(new StringReader(str));
            String Name = string.Empty;
            int Length = 0, Pos = 0;

            // the first entry is a bit different format
            while (reader.Read())
            {
                if (reader.TokenType == JsonToken.PropertyName)
                {
                    if (reader.Value.Equals("TypeName"))
                        Name = reader.ReadAsString();
                    reader.Read();
                    Length = reader.ReadAsInt32() ?? 0;
                    rv.Add(Name, Tuple.Create(0, Length));
                    break;
                }
            }

            // after the first entry we have a fairly consistant format of entries (tag is skipped between name & pos)
            while (reader.Read())
            {
                if (reader.TokenType == JsonToken.PropertyName)
                {
                    if (reader.Value.Equals("MemberName"))
                    {
                        Name = reader.ReadAsString();
                        do { reader.Read(); } while (reader.TokenType != JsonToken.PropertyName);
                        do { reader.Read(); } while (reader.TokenType != JsonToken.PropertyName);
                        Pos = reader.ReadAsInt32() ?? 0;
                        do { reader.Read(); } while (reader.TokenType != JsonToken.PropertyName);
                        Length = reader.ReadAsInt32() ?? 0;
                        rv.Add(Name, Tuple.Create(Pos, Length));
                    }
                }
            }
            return rv;

        }

        public async static Task<string> TypeDef(string name, CODEVIEW_HEADER cvh) => await GET($"typedef/x?type={name}&guid={cvh.aGuid:N}&age={cvh.Age:X1}&PDB={cvh.PdbName}&baseva={cvh.BaseVA}");
        public async static Task<string> FromName(string name, CODEVIEW_HEADER cvh) => await GET($"SymFromName/x?symname={name}&guid={cvh.aGuid:N}&age={cvh.Age:X1}&PDB={cvh.PdbName}&baseva={cvh.BaseVA}");
        public async static Task<string> FromAddress(string address, CODEVIEW_HEADER cvh) => await GET($"SymFromName/x?symaddr={address}&guid={cvh.aGuid:N}&age={cvh.Age:X1}&PDB={cvh.PdbName}&baseva={cvh.BaseVA}");

        static ExpandoObjectConverter converter = new ExpandoObjectConverter();
        static ConcurrentDictionary<string, Tuple<String, ExpandoObject>> _dyn_cache = new ConcurrentDictionary<string, Tuple<String, ExpandoObject>>();
        static ConcurrentDictionary<string, Task<string>> _web_cache = new ConcurrentDictionary<string, Task<string>>();

        // Returns JSON string
        public async static Task<string> GET(string queryStr = null, 
            //string url = "http://zammey:7071/api/")
            string url = "https://pdb2json.azurewebsites.net/api/")
        {
            var fullUri = $"{url}{queryStr}";
            return await GetWebPageAsync(fullUri);
        }

        static Task<string> GetWebPageAsync(string uri)
        {   
            if (_web_cache.TryGetValue(uri, out Task<string> downloadTask)) return downloadTask;
            return _web_cache[uri] = new WebClient().DownloadStringTaskAsync(uri);
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
    }
}
