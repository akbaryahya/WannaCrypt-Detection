using System;
using System.Collections.ObjectModel;
using System.Drawing;
using System.Windows.Forms;
using Microsoft.Win32;
using System.Management.Automation;
using System.Security.Principal;
using System.Threading;

namespace WannaCrypt_Detection
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }
        public bool IsUserAdministrator()
        {
            bool isAdmin;
            try
            {
                WindowsIdentity user = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(user);
                isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (UnauthorizedAccessException ex)
            {
                isAdmin = false;
            }
            catch (Exception ex)
            {
                isAdmin = false;
            }
            return isAdmin;
        }
        static string IsWindows10()
        {
            var reg = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            return (string)reg.GetValue("ProductName");
        }

        static string IsSMBold() 
        {
            var reg = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters");
            return (string)reg.GetValue("SMB1");
        }
        
        static void IsSMBnew()
        {
            using (PowerShell PowerShellInstance = PowerShell.Create())
            {
                // this script has a sleep in it to simulate a long running script
                PowerShellInstance.AddScript("dism /online /Get-Features");

                // begin invoke execution on the pipeline
                IAsyncResult result = PowerShellInstance.BeginInvoke();

                // do something else until execution has completed.
                // this could be sleep/wait, or perhaps some other work
                while (result.IsCompleted == false)
                {
                    Console.WriteLine("Waiting for pipeline to finish...");
                    Thread.Sleep(1000);

                    // might want to place a timeout here...
                }
                foreach (PSObject output2 in PowerShellInstance.Invoke())
                {
                    Console.WriteLine(output2);
                }
                Console.WriteLine("Finished!");
            }
        }

        private void Ceksaya_Click(object sender, EventArgs e)
        {
            //cek windows
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

            //cek SMB, TODO: cek windows 7
            IsSMBnew();
            var ismb = IsSMBold();
            SMB_Lable.Text = ismb;

        }

        private void CekFast(object sender, EventArgs e)
        {
            var sayaadmin = IsUserAdministrator();
            if (sayaadmin)
            {
                Admin_Label.ForeColor = Color.Green;
                Admin_Label.Text = "YES";
            }
            else
            {
                Admin_Label.ForeColor = Color.Red;
                Admin_Label.Text = "NO";
            }
        }
    }
}
