
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

namespace inVtero.net.Support
{
    public class ProgressBarz
    {
        public static ConsoleColor pBarColor;
        public static int Progress;

        public static bool DisableProgressBar = false;

        private static int startOnLine;
        private static char progressBarCharacter = '\u2592';
        private static int CurrTop;

        static ProgressBarz() { }

        public static void  RenderConsoleProgress(int percentage)
        {
            if (DisableProgressBar) return;

            Progress = percentage;
            if (CursorTop > 1 && CurrTop < BufferHeight - 2)
            {
                CursorTop++;
                CurrTop = CursorTop;
                // this means we need to scroll
                //if (CurrTop >= WindowHeight)
                //MoveBufferArea(0, CurrTop, BufferWidth, BufferHeight - CurrTop, 0, CurrTop);
                startOnLine = CurrTop - 1;
            }  

            CursorVisible = false;
            var originalColor = ForegroundColor;
            var origback = BackgroundColor;
            ForegroundColor = pBarColor;
            CursorLeft = 0;

            var width = Console.WindowWidth - 1;
            var newWidth = ((width * percentage) / 100);
            var progBar = new StringBuilder(new string(progressBarCharacter, newWidth)).Append(new string(' ', width - newWidth));
            Write(progBar.ToString());


            CursorTop = startOnLine;
            CursorLeft = 0;
            ForegroundColor = originalColor;
            CursorVisible = true;
        }
    }
}