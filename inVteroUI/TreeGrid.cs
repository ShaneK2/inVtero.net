using inVtero.net;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Threading;

namespace inVteroUI
{
    public class TreeGrid
    {
        public TreeGrid(Vtero vtero, dynamic root)
        {
            Thread t = new Thread(new ThreadStart(() =>
            {
                var dc = new xStructInfoViewModel(vtero, root);
                var w = new ProcTree();
                w.DataContext = dc;
                w.PropGrid.SelectedObject = new DictionaryAdapter<string, object>(root);

                w.Show();
                Dispatcher.Run();
            }));
            t.SetApartmentState(ApartmentState.STA);
            t.IsBackground = true;
            t.Start();
        }
    }
}
