using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.IO;
using inVtero.net;
using inVtero.net.Support;
using System.Globalization;
using ICSharpCode.AvalonEdit.Highlighting;
using System.Xml;

/// <summary>
/// TODO: appropiate UI :)
/// </summary>
namespace inVteroUI
{
     /// <summary>
    /// Interaction logic for MemNavWin.xaml
    /// </summary>
    public partial class MemNavWin : Window
    {
        public MemNavWin()
        {
            InitializeComponent();
            foreach (var type in Enum.GetNames(typeof(MemNavViewModel.BlockType)))
                cbViewSelector.Items.Add(type);
            cbViewSelector.SelectedIndex = 2;
        }

        private void lvBlocks_Selected(object sender, RoutedEventArgs e)
        {
            MemNavViewModel vm = DataContext as MemNavViewModel;
            if (vm != null && vm.SelectedProc != null && lvBlocks.SelectedItem != null)
            {
                var ms = lvBlocks.SelectedItem as MemSection;
                if(ms != null)
                    tbAddress.Text = ms.Address.ToString("x");
            }
        }

        /// <summary>
        /// TODO: import intra/block stuff from EhTrace Agasm.cpp 
        ///   * Then we can do local: blah stuff etc... maybe do a little graph mode with MSAGL
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnDiss_Click(object sender, RoutedEventArgs e)
        {
            MemNavViewModel vm = DataContext as MemNavViewModel;
            if (vm != null && vm.SelectedProc != null)
            {

                IHighlightingDefinition instructionSyntax = null;
                using (Stream s = typeof(MemNavWin).Assembly.GetManifestResourceStream("inVteroUI.InstructionSyntax.xshd"))
                {
                    if (s != null)
                        using (XmlReader reader = new XmlTextReader(s))
                            instructionSyntax = ICSharpCode.AvalonEdit.Highlighting.Xshd.HighlightingLoader.Load(reader, HighlightingManager.Instance);
                }
                avaEdit.SyntaxHighlighting = instructionSyntax;

                ulong DisAddr = 0;
                ulong.TryParse(tbAddress.Text, NumberStyles.AllowHexSpecifier, System.Globalization.CultureInfo.InvariantCulture, out DisAddr);
                if(DisAddr != 0)
                {
                    var asmBytes = vm.SelectedProc.GetVirtualByte((long) DisAddr);

                    var asmCodes = Capstone.Dissassemble(asmBytes, asmBytes.Length, DisAddr, true);
                    StringBuilder sb = new StringBuilder();
                    foreach(var code in asmCodes)
                        sb.AppendLine($"0x{code.insn.address:X} \t {code.insn.mnemonic} \t {code.insn.operands}");

                    avaEdit.Text = sb.ToString();
                }
            }
        }

        private void lvSymbols_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            MemNavViewModel vm = DataContext as MemNavViewModel;
            if (vm != null && vm.SelectedProc != null)
            {
                var ms = lvSymbols.SelectedItem as Tuple<string, ulong, ulong>;
                if(ms != null)
                    tbAddress.Text = ms.Item2.ToString("x");
            }
        }

        byte[] CurrAss;
        ulong DisAddr = 0;

        private void btnAss_Click(object sender, RoutedEventArgs e)
        {
            ulong.TryParse(tbAddress.Text, NumberStyles.AllowHexSpecifier, System.Globalization.CultureInfo.InvariantCulture, out DisAddr);
            var PatchAddr = (long) DisAddr;
            MemNavViewModel vm = DataContext as MemNavViewModel;
            if (vm != null && vm.SelectedProc != null)
            {
                var p = vm.SelectedProc;
                var hw = p.MemAccess.VirtualToPhysical(p.CR3Value, PatchAddr);

                var file_block_offset = p.MemAccess.OffsetToMemIndex(hw.NextTable_PFN);

                var FileAddr = file_block_offset + (PatchAddr & 0xfff);

                var writer = new FileStream(vm.vtero.MemFile, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);

                writer.Seek(FileAddr, SeekOrigin.Begin);

                writer.Write(CurrAss, 0, CurrAss.Length);

                writer.Close();
                MessageBox.Show($"Write back to address {DisAddr:x} assembly code done.");
            }
        }

        private void tbSymMatch_PreviewKeyUp(object sender, KeyEventArgs e)
        {
            MemNavViewModel vm = DataContext as MemNavViewModel;
            var ms = lvBlocks.SelectedItem as MemSection;
            if (vm != null && vm.SelectedProc != null && ms != null)
                lvSymbols.ItemsSource = vm.SelectedProc.MatchSymbols(tbSymMatch.Text, ms.Name);
        }

        private void tbAsm_PreviewKeyUp(object sender, KeyEventArgs e)
        {
            ulong.TryParse(tbAddress.Text, NumberStyles.AllowHexSpecifier, System.Globalization.CultureInfo.InvariantCulture, out DisAddr);

            // setup dropdown for options
            // read assembly and output to box
            CurrAss = Keystone.Assemble(tbAsm.Text, DisAddr, ks_opt_value.KS_OPT_SYNTAX_INTEL | ks_opt_value.KS_OPT_SYNTAX_RADIX16);
            string hex = BitConverter.ToString(CurrAss).Replace("-", " ");

            tbAsmOut.Text = hex;
        }
    }
}
