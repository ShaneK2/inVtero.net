using ImpromptuInterface.MVVM;
using inVtero.net;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace inVteroUI
{
    public class xStructInfoViewModel : ImpromptuViewModel
    {
        public Vtero vtero;

        public dynamic selectedObject;
        public dynamic SelectedObject
        {
            get { return selectedObject; }
            set
            {
                if (selectedObject != value)
                {
                    selectedObject = value;
                    OnPropertyChanged("SelectedObject");
                }
            }
        }
        public xStructInfoViewModel(Vtero v, dynamic root)
        {
            vtero = v;
            SelectedObject = root;

            PropertyChanged += (sender, e) => Command.SelectedObject.RaiseCanExecuteChanged();
        }
    }
}
