using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using inVtero.net;

namespace inVteroUI
{
    public class MemNavViewModel : ViewModelBase
    {
        public Vtero vtero;
        public enum BlockType
        {
            Byte,
            Pointer64,
            Instructions64,
            PEHeader
        }
        public BlockType RenderType { get;set; }
        public List<DetectedProc> ProcList { get; private set; }
        DetectedProc selectedProc;
        public DetectedProc SelectedProc
        {
            get { return selectedProc; }
            set
            {
                if (selectedProc != value)
                {
                    selectedProc = value;
                    selectedProc.MemAccess = vtero.MemAccess;
                    //selectedProc.ScanAndLoadModules();
                    //selectedProc.ListVad(selectedProc.VadRootPtr);
                    // TODO: there's a lot of exceptions in this call, should trim/optimize it out
                    selectedProc.CopySymbolsForVad(vtero.KernelProc);
                    selectedProc.MergeVAMetaData();
                    OnPropertyChanged("SelectedProc");
                }
            }
        }
       
        public MemNavViewModel(Vtero v)
        {
            vtero = v;
            vtero.KernelProc.InitSymbolsForVad();
            ProcList = vtero.Processes.ToList();
            RenderType = BlockType.Instructions64;
        }
    }
}
