
// Shane.Macaulay@IOActive.com Copyright (C) 2013-2015

//Copyright(C) 2015 Shane Macaulay

//This program is free software; you can redistribute it and/or
//modify it under the terms of the GNU General Public License
//as published by the Free Software Foundation.

//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
//GNU General Public License for more details.

//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

using System;
using System.Text;
using static System.Console;
using PowerArgs.Cli;
using PowerArgs;

namespace inVtero.net.Support
{
    public static class ProgressBarz
    {
        public static ConsoleColor pBarColor;
        public static int Progress;

        public static bool DisableProgressBar = false;

        public static ConsoleString BaseMessage;
        private static char progressBarCharacter = '\u2592';
        static int LastProgLine;
        static int SavePos;

        public static CliProgressBar Bar;

        static ProgressBarz() {
            Bar = new CliProgressBar("Initalizing...");
        }

        public static void RenderConsoleProgress(int percentage)
        {
            Progress = percentage;

            if (DisableProgressBar) return;

            CursorVisible = false;
            const int BarHeight = 3;
            var BarStart = (WindowTop + WindowHeight - 1) - BarHeight;

            CursorTop = BarStart;
            Bar.Progress = percentage / 100.00;
            Bar.Message = BaseMessage.AppendUsingCurrentFormat($".  {percentage} %");
            Bar.Render();

            CursorTop = BarStart-1;


            /*
            Progress = percentage;
            CursorVisible = false;

            var BottomOfCon = WindowTop + WindowHeight - 1;
            var BottomOfBuffer = BufferHeight - WindowHeight - BarHeight;
            SavePos = CursorTop;
            var MaxText = (WindowTop + WindowHeight - 1) - BarHeight;
            var BarLine = MaxText + 1;
            while (SavePos-- >= MaxText)
                WriteLine("\t\t\t\t\t".PadRight(WindowWidth));
            SavePos = CursorTop;

            //if (LastProgLine != SavePos && CursorTop + BarHeight >= BufferHeight)
            //WriteLine();

            var originalColor = ForegroundColor;
            var origback = BackgroundColor;
            ForegroundColor = pBarColor;
            CursorLeft = 0;

            //LastProgLine = CursorTop = BottomOfCon - BarHeight;
            var width = Console.WindowWidth - 4;
            var newWidth = ((width * percentage) / 100);  // incase some change happened

            CursorTop = BarLine;
            Bar.Width = newWidth; 
            Bar.Progress = percentage / 100.00;
            Bar.Render();

//            var progBar = new StringBuilder(new string(progressBarCharacter, newWidth)).Append(new string(' ', width - newWidth));
//            Write(progBar.ToString());

            CursorLeft = 0;
            ForegroundColor = originalColor;
            CursorTop = SavePos;
            CursorVisible = true;
            */

        }
    }
}