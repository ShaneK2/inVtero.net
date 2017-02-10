// Copyright(C) 2017 Shane Macaulay smacaulay@gmail.com
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or(at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.If not, see<http://www.gnu.org/licenses/>.

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