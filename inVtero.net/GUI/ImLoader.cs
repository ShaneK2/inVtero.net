using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace inVtero.net.GUI
{
    public class ImLoader
    {
        public ImLoader(Vtero vtero, byte[] block, long address)
        {
            Thread t = new Thread(new ThreadStart(() => {

                var im = new ImWindow(block, address);
                im.RunWindowLoop();
            }));
            t.SetApartmentState(ApartmentState.STA);
            t.IsBackground = true;
            t.Start();
        }
    }
}
