using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Management;
using System.Windows.Forms;
using Microsoft.Win32;
using System.Management.Automation;
using System.Net.Sockets;
using System.Security.Principal;
using System.Threading;
using WUApiLib;

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
        public bool IsProcessOpen(string name)
        {
            foreach (Process clsProcess in Process.GetProcesses())
            {
                Logme(Color.Gold, clsProcess.ProcessName);
                if (clsProcess.ProcessName.Contains(name))
                {
                    return true;
                }
            }
            return false;
        }
        public bool FindService(string nama) 
        {
            using (PowerShell ps = PowerShell.Create())
            {
                ps.AddScript("Get-Service | Select Status,Name,DisplayName");//-Name *lan*
                IAsyncResult result = ps.BeginInvoke();
                while (result.IsCompleted == false)
                {
                    Logme(Color.Gold, "Waiting for pipeline to finish...");
                    Thread.Sleep(1000);
                }
                Logme(Color.Gold, "Finished!");
                foreach (PSObject resultx in ps.Invoke())
                {
                    Logme(Color.Gold, $"{resultx.Members["Status"].Value}|{resultx.Members["Name"].Value}|{resultx.Members["DisplayName"].Value}");
                    if (resultx.Members["Name"].Value.ToString().Contains(nama))
                    {
                        return true;
                    }
                }
            }
            return false;
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
        
        public bool IsSMBnew()
        {
            //or use https://github.com/cseelye/windiskhelper/blob/28be60045e79c557eb33558ee65faf3e7d84629c/MicrosoftInitiator.cs#L3855
            using (PowerShell ps = PowerShell.Create())
            {
                ps.AddScript("Get-SmbServerConfiguration | Select EnableSMB1Protocol, EnableSMB2Protocol");
                IAsyncResult result = ps.BeginInvoke();
                while (result.IsCompleted == false)
                {
                    Logme(Color.Gold, "Waiting for pipeline to finish...");
                    Thread.Sleep(1000);
                }
                Logme(Color.Gold, "Finished!");
                foreach (PSObject resultx in ps.Invoke())
                {
                    Logme(Color.Gold, $"{resultx.Members["EnableSMB1Protocol"].Value}|{resultx.Members["EnableSMB2Protocol"].Value}");
                    if (resultx.Members["EnableSMB1Protocol"].Value.ToString() == "True" && resultx.Members["EnableSMB2Protocol"].Value.ToString() == "True")
                    {
                        return true;
                    }
                }
            }
            if (FindService("LanmanServer"))
            {
                return true;
            }
            return false;
        }
        public bool FindUpdates(string patch)
        {
            //var session = new UpdateSession();
            //var searcher = session.CreateUpdateSearcher();
            //searcher.ServerSelection = ServerSelection.ssWindowsUpdate;
            //ISearchResult searchresult = searcher.Search("");
            //UpdateCollection updatecollection = searchresult.Updates;
            //Console.WriteLine("Found " + updatecollection.Count + " updates.");

            //foreach (IUpdate5 update in updatecollection)
            //{
            //    Console.WriteLine(update.Title);
            //}
            var updateSession = new UpdateSession();
            var updateSearcher = updateSession.CreateUpdateSearcher();
            var count = updateSearcher.GetTotalHistoryCount();
            if (count == 0)
                return false;

            var history = updateSearcher.QueryHistory(0, count);
            for (int i = 0; i < count; i++)
            {
                Logme(Color.Gold, $"{history[i].Title}");
                if (history[i].Title.Contains("KB"+patch))
                {
                    return true;
                }
            }
            return false;
        }

        public void startcek()
        {
            Ceksaya.Enabled = false;
            ThreadPool.QueueUserWorkItem(state =>
            {
                //cek windows, TODO: cek bit
                var ismy = IsWindows10();
                if (ismy.Contains("Windows 10"))
                {
                    ThreadHelperClass.SetText(this, Windows_Label, ismy);
                    ThreadHelperClass.SetColor(this,Windows_Label,Color.Green);
                }
                else
                {
                    ThreadHelperClass.SetText(this, Windows_Label, ismy);
                    ThreadHelperClass.SetColor(this, Windows_Label, Color.Red);
                }

                //cek SMB, TODO: cek windows 7
                var ismb = IsSMBnew();
                if (!ismb)
                {
                    ThreadHelperClass.SetText(this, SMB_Lable, "YES");
                    ThreadHelperClass.SetColor(this, SMB_Lable, Color.Green);
                }
                else
                {
                    ThreadHelperClass.SetText(this, SMB_Lable, "NO");
                    ThreadHelperClass.SetColor(this, SMB_Lable, Color.Red);
                }

                //cek port
                ThreadHelperClass.SetText(this, Port_Label, $"139 {IsPortClose(139)} | 445 {IsPortClose(445)} | 3389 {IsPortClose(3389)}");

                ThreadHelperClass.SetText(this, Patch_Lable, $"{ispatchsafe()} %");

                ThreadHelperClass.SetText(this, WC_Label, $"{iswcgod()} %"); 

                /*
                tasksche,mssecsvc,taskdl,taskse,WanaDecryptor,Taskse
                Windows XP: 4012598
                Windows Vista SP2: 4012598,4012598
                Windows Server 2008: 4012598
                Windows 7/Windows Server 2008: 4012212,4012215
                Windows 8.1/Windows Server 2012/Windows Server 2012 R2: 4012213,4012216 
                Windows 10: 4012606,4013198,4013429
                Windows Server 2016: 4013429
                */

                //END
                Ceksaya.BeginInvoke((Action)delegate { Ceksaya.Enabled = true; });
            });
        }

        private void Ceksaya_Click(object sender, EventArgs e)
        {
            startcek();
        }

        public int ispatchsafe()
        {
            List<string> listcek = new List<string>(new[] { "4012212", "4012217", "4015551", "4019216", "4012216", "4015550", "4019215", "4013429", "4019472", "4015217", "4015438", "4016635"});
            var isme = 0;
            foreach (var k in listcek) 
            {
                if (FindUpdates(k))
                {
                    isme++;
                }
            }
            var relp = Convert.ToDouble(isme) / Convert.ToDouble(listcek.Count) * 100;
            return (int)Math.Floor(relp); 
        }
        public int iswcgod()
        {
            List<string> listcek = new List<string>(new[] { "mssecsvc", "tasksche", "@WanaDecryptor@", "taskdl", "Taskse"});
            var isme = 0;
            foreach (var k in listcek)
            {
                if (IsProcessOpen(k))
                {
                    isme++;
                }
            }
            var relp = Convert.ToDouble(isme) / Convert.ToDouble(listcek.Count) * 100;
            return (int)Math.Floor(relp);
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
        public static DateTime Timex = DateTime.Now;
        public static string logtxt = Path.Combine(Program.Path, $"log-{Timex:yyyyMMdd}.txt");
        public static void AddLog(string line, string Log, bool time = true)
        {
            if (!File.Exists(Log))
            {
                File.Create(Log);
            }
            try
            {
                TextWriter tw = new StreamWriter(Log, true);
                var timex = $"[{DateTime.Now:G}] ";
                if (!time)
                    timex = "";

                tw.WriteLine(timex + line);
                tw.Close();
            }
            catch (Exception)
            {
                // Probably used by other process error
            }
        }
        public void Logme(Color color, string text)
        {
            if (LogMe.InvokeRequired)
            {
                try
                {
                    Invoke(new Action<Color, string>(Logme), color, text);
                }
                catch (Exception)
                {
                    //look bug
                }
            }
            else
            {
                try
                {
                    LogMe.SelectionColor = color;
                    LogMe.AppendText(text + "\n");
                    LogMe.SelectionStart = LogMe.Text.Length;
                    LogMe.ScrollToCaret();
                    AddLog(text, logtxt);
                }
                catch (Exception)
                {
                    //noting here
                }

            }
        }
    }
    public static class ThreadHelperClass
    {
        //http://stackoverflow.com/a/15831292
        delegate void SetTextCallback(Form f, Control ctrl, string text);
        delegate void SetColorCallback(Form f, Control ctrl, Color text);
        public static void SetText(Form form, Control ctrl, string text)
        {
            if (ctrl.InvokeRequired)
            {
                SetTextCallback d = SetText;
                form.Invoke(d, form, ctrl, text);
            }
            else
            {
                ctrl.Text = text;
            }
        }
        public static void SetColor(Form form, Control ctrl, Color text)
        {
            if (ctrl.InvokeRequired)
            {
                SetColorCallback d = SetColor;
                form.Invoke(d, form, ctrl, text);
            }
            else
            {
                ctrl.ForeColor = text;
            }
        }
    }
}
