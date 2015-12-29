
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

        private static char progressBarCharacter = '\u2592';
        static int LastProgLine;
        static int SavePos;

        static ProgressBarz() { }

        public static void RenderConsoleProgress(int percentage)
        {
            if (DisableProgressBar) return;
            Progress = percentage;
            CursorVisible = false;

            var BottomOfCon = WindowTop + WindowHeight - 1;
            var BottomOfBuffer = BufferHeight - WindowHeight - 1;
            SavePos = CursorTop;

            if (LastProgLine != SavePos && CursorTop + 1 >= BufferHeight)
                WriteLine();

            var originalColor = ForegroundColor;
            var origback = BackgroundColor;
            ForegroundColor = pBarColor;
            CursorLeft = 0;

            LastProgLine = CursorTop = BottomOfCon;
            var width = Console.WindowWidth - 1;
            var newWidth = ((width * percentage) / 100);
            var progBar = new StringBuilder(new string(progressBarCharacter, newWidth)).Append(new string(' ', width - newWidth));
            Write(progBar.ToString());


            CursorTop = SavePos;
            CursorLeft = 0;
            ForegroundColor = originalColor;
            CursorTop = SavePos;
            CursorVisible = true;
        }
    }
}