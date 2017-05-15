using System;
using System.Collections.ObjectModel;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;
using Microsoft.Win32;
using System.Management.Automation;
using System.Net.Sockets;
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

        static bool IsPortClose(int port = 80)
        {
            using (TcpClient tcpClient = new TcpClient())
            {
                try
                {
                    tcpClient.Connect("127.0.0.1", port);
                    return false;
                }
                catch (Exception)
                {
                    //noting here
                }
            }
            return true;
        }
        
        static bool IsSMBnew()
        {
            //or use https://github.com/cseelye/windiskhelper/blob/28be60045e79c557eb33558ee65faf3e7d84629c/MicrosoftInitiator.cs#L3855
            using (PowerShell ps = PowerShell.Create())
            {
                ps.AddScript("Get-SmbServerConfiguration | Select EnableSMB1Protocol, EnableSMB2Protocol");
                IAsyncResult result = ps.BeginInvoke();
                while (result.IsCompleted == false)
                {
                    Console.WriteLine("Waiting for pipeline to finish...");
                    Thread.Sleep(1000);
                }
                Console.WriteLine("Finished!");
                foreach (PSObject resultx in ps.Invoke())
                {
                    Console.WriteLine($"{resultx.Members["EnableSMB1Protocol"].Value}|{resultx.Members["EnableSMB2Protocol"].Value}");
                    if (resultx.Members["EnableSMB1Protocol"].Value.ToString() == "True" && resultx.Members["EnableSMB2Protocol"].Value.ToString() == "True")
                    {
                        return true;
                    }
                }
            }
            return false;
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
            var ismb = IsSMBnew();
            if (!ismb)
            {
                SMB_Lable.ForeColor = Color.Green;
                SMB_Lable.Text = "YES";
            }
            else
            {
                SMB_Lable.ForeColor = Color.Red;
                SMB_Lable.Text = "NO";
            }

            //cek port
            Port_Label.Text = $"139 {IsPortClose(139)} 445 {IsPortClose(445)} 3389 {IsPortClose(3389)}"; 

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
