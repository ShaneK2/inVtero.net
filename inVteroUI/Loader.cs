using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Threading;
using inVtero.net;

namespace inVteroUI
{
    public class Loader
    {
        public Loader(Vtero vtero)
        {
            Thread t = new Thread(new ThreadStart(() => {

                var dc = new MemNavViewModel(vtero);
                var w = new MemNavWin();
                w.DataContext = dc;

                w.Show();
                Dispatcher.Run();
            }));
            t.SetApartmentState(ApartmentState.STA);
            t.IsBackground = true;
            t.Start();
        }
    }
}
