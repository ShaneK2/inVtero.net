using System;
using System.Collections.Generic;
using System.Text;
using static Dia2Sharp.DebugHelp;

namespace Dia2Sharp
{
    public class DiaSource
    {
        CODEVIEW_HEADER CV;
        public DiaSource(CODEVIEW_HEADER cv)
        {
            CV = cv;
        }

        public void loadDataFromPdb(string pdbPath)
        {

        }
        public void openSession(out IDiaSession Sess)
        {
            Sess = new DiaSession();
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

    public class DiaSession : IDiaSession
    {
        public IDiaSymbol globalScope { get; set; }
        public ulong loadAddress { get; set; }

        void IDiaSession.findChildren(IDiaSymbol parent, DebugHelp.SymTagEnum symTag, string name, uint compareFlags, out IDiaEnumSymbols ppResult)
        {
            ppResult = null;
            return;
        }
        void IDiaSession.getSymbolsByAddr(out IDiaEnumSymbolsByAddr ppEnumbyAddr)
        {
            ppEnumbyAddr = null;
            return;
        }
    }
    public class EnumSymbols : IDiaEnumSymbols
    {
        public int count { get; }

        public void Clone(out IDiaEnumSymbols ppenum)
        {
            ppenum = this;
            return;
        }

        public IEnumerator<IDiaSymbol> GetEnumerator()
        {
            return null;
        }

        public IDiaSymbol Item(uint index)
        {
            return null;
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
    }

    public class DiaSymbol : IDiaSymbol
    {
        public uint bitPosition { get; }
        public uint symTag { get; }
        public int offset { get; }
        public dynamic value { get; }
        public uint locationType { get; }
        public IDiaSymbol type { get; }
        public string name { get; }
        public ulong length { get; }
        public ulong virtualAddress { get; }

        void IDiaSymbol.findChildren(SymTagEnum symTag, string name, uint compareFlags, out IDiaEnumSymbols ppResult)
        {
            ppResult = null;
            return;
        }
    }

    /// <summary>
    /// Manage local symbol cache
    /// </summary>
    public class Dia3 
    {
        CODEVIEW_HEADER CV;

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
    }
}
