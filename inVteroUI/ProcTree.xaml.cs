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

namespace inVteroUI
{
    /// <summary>
    /// Interaction logic for ProcTree.xaml
    /// </summary>
    public partial class ProcTree : Window
    {
        public ProcTree()
        {
            InitializeComponent();
        }

        private void OnControlGetFocus(object sender, System.Windows.RoutedEventArgs e)
        {
            PropGrid.SelectedObject = e.Source;
        }
    }
}
