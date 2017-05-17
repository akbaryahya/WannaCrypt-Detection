using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using Microsoft.Win32;
using System.Management.Automation;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Threading;
using WUApiLib;
// ReSharper disable LocalizableElement

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
            catch (UnauthorizedAccessException)
            {
                isAdmin = false;
            }
            catch (Exception)
            {
                isAdmin = false;
            }
            return isAdmin;
        }
        static string IsWindows()
        {
            var reg = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            if (reg != null) return (string)reg.GetValue("ProductName");
            return "Not known";
        }
        public string InternalReadAllText(string path, Encoding encoding)
        {
            string result;
            using (StreamReader streamReader = new StreamReader(path, encoding))
            {
                result = streamReader.ReadToEnd();
            }
            return result;
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
        public bool KillPs(string id, bool waitForExit = false) 
        {
            var isme = Process.GetProcessesByName(id);
            if (isme.Any())
            {
                foreach (var p in isme)
                {
                    if (p == null || p.HasExited) return false;

                    p.Kill();
                    if (waitForExit)
                    {
                        p.WaitForExit();
                    }
                    return true;
                }
            }
            return false;
        }
        public string GetNamePs(string id)
        {
            var isme = Process.GetProcessesByName(id);
            if (isme.Any())
            {
                foreach (var p in isme)
                {
                    return p.MainModule.FileName;
                }
            }
            return "";
        }
        public bool FindService(string nama) 
        {
            foreach (PSObject resultx in PowerShellsc("Get-Service | Select Status,Name,DisplayName"))
            {
                Logme(Color.Gold, $"{resultx.Members["Status"].Value}|{resultx.Members["Name"].Value}|{resultx.Members["DisplayName"].Value}");
                if (resultx.Members["Name"].Value.ToString().Contains(nama))
                {
                    if ((resultx.Members["Status"].Value).ToString().Contains("Running"))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        //TODO: udp
        public bool IsPortOpen(int port = 80, string host = "127.0.0.1", int timeout = 1000*20)
        {
            //http://stackoverflow.com/a/38258154
            try
            {
                using (var client = new TcpClient())
                {
                    var result = client.BeginConnect(host, port, null, null);
                    var success = result.AsyncWaitHandle.WaitOne(timeout);
                    if (!success)
                    {
                        return false;
                    }
                    client.EndConnect(result);
                }

            }
            catch
            {
                return false;
            }
            return true;
        }

        public bool IsSmBstop()
        {
            //or use https://github.com/cseelye/windiskhelper/blob/28be60045e79c557eb33558ee65faf3e7d84629c/MicrosoftInitiator.cs#L3855
            foreach (PSObject resultx in PowerShellsc("Get-SmbServerConfiguration | Select EnableSMB1Protocol, EnableSMB2Protocol"))
            {
                Logme(Color.Gold, $"{resultx.Members["EnableSMB1Protocol"].Value}|{resultx.Members["EnableSMB2Protocol"].Value}");
                if (resultx.Members["EnableSMB1Protocol"].Value.ToString() == "False" && resultx.Members["EnableSMB2Protocol"].Value.ToString() == "False")
                {
                    return true; //Windows 10
                }
            }
            //Windows 7
            return !FindService("LanmanServer");
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

        public string Isx64() 
        {
            return Environment.Is64BitOperatingSystem ? "64bit" : "32bit";
        }

        public void Startcek()
        {
            Ceksaya.Enabled = false;
            ThreadPool.QueueUserWorkItem(state =>
            {
                //cek windows
                var ismy = IsWindows();
                
                ThreadHelperClass.SetText(this, Windows_Label, $"{ismy} ({Isx64()})");
                ThreadHelperClass.SetColor(this, Windows_Label, ismy.Contains("Windows 10") ? Color.Green : Color.Red);

                //cek SMB
                var ismb = IsSmBstop();
                if (ismb)
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
                ThreadHelperClass.SetText(this, Port_Label, $"139 {!IsPortOpen(139)} | 445 {!IsPortOpen(445)} | 3389 {!IsPortOpen(3389)}");

                ThreadHelperClass.SetText(this, Patch_Lable, $"{Ispatchsafe()} %");

                ThreadHelperClass.SetText(this, WC_Label, $"{Iswcgod()} %"); 

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
            Startcek();
        }

        readonly List<string> _kb = new List<string>(new[] { "4012212", "4012213", "4012214", "4012215", "4012216", "4012217", "4012598", "4012606", "4013198", "4013429", "4015217", "4015438", "4015549", "4015550", "4015551", "4015552", "4015553", "4016635", "4019215", "4019216", "4019264", "4019472" });
        readonly List<string> _killz = new List<string>(new[] { "mssecsvc", "tasksche", "@WanaDecryptor@", "taskdl", "Taskse" });
        public int Ispatchsafe()
        {
            var isme = 0;
            foreach (var k in _kb) 
            {
                if (FindUpdates(k))
                {
                    isme++;
                }
            }
            var relp = Convert.ToDouble(isme) / Convert.ToDouble(_kb.Count) * 100;
            return (int)Math.Floor(relp); 
        }
        public int Iswcgod()
        {
            var isme = 0;
            foreach (var k in _killz)
            {
                if (IsProcessOpen(k))
                {
                    isme++;
                }
            }
            var relp = Convert.ToDouble(isme) / Convert.ToDouble(_killz.Count) * 100;
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
        public static string Logtxt = Path.Combine(Program.Path, $"log-{Timex:yyyyMMdd}.txt");
        public static void AddLog(string line, string log, bool time = true)
        {
            if (!File.Exists(log))
            {
                File.Create(log);
            }
            try
            {
                TextWriter tw = new StreamWriter(log, true);
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
                    //noting here
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
                    AddLog(text, Logtxt);
                }
                catch (Exception)
                {
                    //noting here
                }

            }
        }

        public Collection<PSObject> PowerShellsc(string sc)
        {
            using (PowerShell ps = PowerShell.Create())
            {
                ps.AddScript(sc);
                IAsyncResult result = ps.BeginInvoke();
                while (result.IsCompleted == false)
                {
                    Logme(Color.Gold, "Waiting for pipeline to finish...");
                    Thread.Sleep(1000);
                }
                Logme(Color.Gold, "Finished!");
                var kk = ps.Invoke();
                return kk;
            }
        }

        private void BlokPort_z_Click(object sender, EventArgs e)
        {
            //TODO: if patch ok
            //netsh advfirewall firewall show rule name="a"
            ExecuteCmd("netsh advfirewall firewall add rule name=SmbPatchIntcp dir=in protocol=tcp localport=139,445,3389 action=block");
            ExecuteCmd("netsh advfirewall firewall add rule name=SmbPatchOuttt dir=out protocol=tcp remoteport=139,445,3389 action=block");
            ExecuteCmd("netsh advfirewall firewall add rule name=SmbPatchInudp dir=in protocol=udp localport=137,138 action=block");
            ExecuteCmd("netsh advfirewall firewall add rule name=SmbPatchouudp dir=out protocol=udp remoteport=137,138 action=block");
            Logme(Color.Green, "Done blok port!");
        }

        public bool SetRegLm(string sub, string name, string value)
        {
            var key = Registry.LocalMachine.CreateSubKey(sub);
            if (key != null)
            {
                key.SetValue(name, value);
                key.Close();
                return true;
            }
            return false;
        }
        private static string ExecuteCmd(string command)
        {
            //https://github.com/L7D/WannaCry-Ransomeware-PortBlocker/blob/master/Firewall.cs#L10
            ProcessStartInfo proInfo = new ProcessStartInfo()
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardInput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                FileName = $@"{Environment.SystemDirectory}\cmd.exe",
                Verb = "runas"
            };
            Process pro = new Process
            {
                StartInfo = proInfo
            };
            pro.Start();
            pro.StandardInput.WriteLine(command);
            pro.StandardInput.Close();
            string resultValue = pro.StandardOutput.ReadToEnd();
            pro.WaitForExit();
            pro.Close();
            resultValue = resultValue.Substring(resultValue.IndexOf(command, StringComparison.Ordinal) + command.Length + 2);
            return resultValue;
        }
        private void smboff_Click(object sender, EventArgs e)
        {
            //SMB server
            var ismy = IsWindows();
            if (!ismy.ContainsAny("Windows XP", "Windows 7", "Windows Server 2008 R2", "Windows Vista", "Windows Server 2008"))
            {
                PowerShellsc("Set-SMBServerConfiguration -EnableSMB1Protocol:$false -Confirm:$false");
                PowerShellsc("Set-SMBServerConfiguration -EnableSMB2Protocol:$false -Confirm:$false");
            }
            else
            {
                var locae = @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
                SetRegLm(locae, "SMB1", "0");
                SetRegLm(locae, "SMB2", "0");
            }

            //SMB client
            //disable SMBv1
            ExecuteCmd("sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi");
            ExecuteCmd("sc.exe config mrxsmb10 start= disabled");
            //disable SMBv2 and SMBv3
            ExecuteCmd("sc.exe config lanmanworkstation depend= bowser/mrxsmb10/nsi");
            ExecuteCmd("sc.exe config mrxsmb20 start= disabled");

            Logme(Color.Gold, "Please restart your pc to see results");
        }

        private void upkill_Click(object sender, EventArgs e)
        {
            var host = $@"{Environment.SystemDirectory}\drivers\etc\hosts";
            try
            {
                if (File.Exists(host))
                {
                    string readText = InternalReadAllText(host,Encoding.UTF8);
                    if (readText != null)
                    {
                        if (!readText.Contains("216.58.197.132"))
                        {
                            File.AppendAllText(host, "216.58.197.132 www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" + Environment.NewLine);
                            File.AppendAllText(host, "216.58.197.132 iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" + Environment.NewLine);
                            File.AppendAllText(host, "216.58.197.132 www.ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com" + Environment.NewLine);
                            File.AppendAllText(host, "216.58.197.132 ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com" + Environment.NewLine);
                            File.AppendAllText(host, "216.58.197.132 www.iuqssfsodp9ifjaposdfjhgosurijfaewrwergwea.com" + Environment.NewLine);
                            File.AppendAllText(host, "216.58.197.132 iuqssfsodp9ifjaposdfjhgosurijfaewrwergwea.com" + Environment.NewLine);
                            File.AppendAllText(host, "216.58.197.132 www.ayylmaotjhsstasdfasdfasdfasdfasdfasdfasdf.com" + Environment.NewLine);
                            File.AppendAllText(host, "216.58.197.132 ayylmaotjhsstasdfasdfasdfasdfasdfasdfasdf.com" + Environment.NewLine);
                            Logme(Color.Green, "OK");
                            return;
                        }
                    }
                }
                Logme(Color.Gold, "No host found or Has been in patch");
            }
            catch (Exception ex)
            {
                Logme(Color.Red, ex.ToString());
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            foreach (var x in _killz) 
            {
                //TODO: hapus file
                Logme(Color.Gold, $"{x}: {GetNamePs(x)}");

                //kill
                if (KillPs(x))
                {
                    Logme(Color.Green, $"{x} Have been killed");
                }
                else
                {
                    Logme(Color.Red, $"{x} Have been killed or not?");
                }
            }
        }
    }

    public static class StringExtensions
    {
        //http://stackoverflow.com/a/3519555
        public static bool ContainsAny(this string haystack, params string[] needles)
        {
            foreach (string needle in needles)
            {
                if (haystack.Contains(needle))
                    return true;
            }

            return false;
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
