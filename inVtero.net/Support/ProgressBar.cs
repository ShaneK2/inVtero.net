
using System;
using System.Text;
using static System.Console;

namespace inVtero.net.Support
{
    public class ProgressBarz
    {
        public static ConsoleColor pBarColor;
        public static int Progress;

        private static int startOnLine;
        private static char progressBarCharacter = '\u2592';
        private static int CurrTop;

        static ProgressBarz() { }

        public static void  RenderConsoleProgress(int percentage)
        {
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