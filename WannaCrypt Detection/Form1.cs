using System;
using System.Drawing;
using System.Windows.Forms;
using Microsoft.Win32;

namespace WannaCrypt_Detection
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        static string IsWindows10()
        {
            var reg = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            return (string)reg.GetValue("ProductName");
        }

        private void Ceksaya_Click(object sender, EventArgs e)
        {
            var ismy = IsWindows10();
            if (ismy.Contains("Windows 10"))
            {
                Windows_Label.ForeColor = Color.Green;
                Windows_Label.Text = ismy;
            }
            else
            {
                Windows_Label.ForeColor = Color.Red;
                Windows_Label.Text = ismy;
            }
        }
    }
}
