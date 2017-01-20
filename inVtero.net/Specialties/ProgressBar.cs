
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
    public static class ProgressBarz
    {
        public static ConsoleColor pBarColor = ConsoleColor.Yellow;
        public static int Progress = 0;

        public static bool DisableProgressBar = false;
        public static bool TextInfo = false;

        private static char progressBarCharacter = '\u2592';
        static int SavePos;

        static ProgressBarz() {
        }

        public static void RenderConsoleProgress(int percentage)
        {
            if (Progress == percentage)
                return;

            Progress = percentage;

            CursorVisible = false;
            const int BarHeight = 1;
            var BarStart = (WindowTop + WindowHeight - 1) - BarHeight;

            CursorTop = BarStart;

            if (!DisableProgressBar)
            {
                CursorTop = BarStart - 1;
                CursorVisible = false;

                var BottomOfCon = WindowTop + WindowHeight - 1;
                var BottomOfBuffer = BufferHeight - WindowHeight - BarHeight;
                var MaxText = (WindowTop + WindowHeight - 1) - BarHeight;
                var BarLine = MaxText + 1;

                var originalColor = ForegroundColor;
                var origback = BackgroundColor;
                ForegroundColor = pBarColor;
                CursorLeft = 0;

                var width = Console.WindowWidth - 4;
                var newWidth = ((width * percentage) / 100);  

                CursorTop = BarLine;

                var progBar = new StringBuilder(new string(progressBarCharacter, newWidth)).Append(new string(' ', width - newWidth));
                Write(progBar.ToString());

                CursorLeft = 0;
                ForegroundColor = originalColor;
                CursorTop = BottomOfCon;
                CursorVisible = true;
            }
            else if (TextInfo && percentage != Progress)
            {
                ForegroundColor = ConsoleColor.DarkBlue;
                BackgroundColor = ConsoleColor.Yellow;
                WriteLine($" {percentage} % ");
            }
        }
    }
}