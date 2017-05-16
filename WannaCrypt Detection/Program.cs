using System;
using System.IO;
using System.Windows.Forms;

namespace WannaCrypt_Detection
{
    static class Program
    {
        public static string Path = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "tmp");
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            // Create missing Files
            Directory.CreateDirectory(Path);

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new Form1());
        }
    }
}
