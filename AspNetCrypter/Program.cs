using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Web.Security.Cryptography;
using System.Web.Util;

namespace LowLevelDesign.AspNetCrypter
{
    public static class Program
    {
        private static readonly Dictionary<string, Purpose> purposeMap = new Dictionary<string, Purpose>(StringComparer.Ordinal) {
            { "owin.cookie", Purpose.User_MachineKey_Protect.AppendSpecificPurposes(
                new [] {
                    "Microsoft.Owin.Security.Cookies.CookieAuthenticationMiddleware",
                    "ApplicationCookie",
                    "v1"}) },
            { "forms.cookie", new Purpose("FormsAuthentication.Ticket") }
        };

        public static void Main(string[] args)
        {
            string validationKeyAsText = null, decryptionKeyAsText = null,
                textToDecrypt = null, purposeKey = null, fileToDecrypt = null;
            bool showhelp = false, isBase64 = false;

            var p = new OptionSet
            {
                { "vk=", "the validation key (in hex)", v => validationKeyAsText = v },
                { "dk=", "the decryption key (in hex)", v => decryptionKeyAsText = v },
                { "p|purpose=", "the encryption context\n(currently only: owin.cookie or forms.cookie)", v => purposeKey = v },
                { "base64", "data is provided in base64 format (otherwise we assume hex)", v => isBase64 = v != null },
                { "i|input=", "input data file (when too big for command line)", v => fileToDecrypt = v },
                { "h|help", "Show this message and exit", v => showhelp = v != null },
                { "?", "Show this message and exit", v => showhelp = v != null }
            };

            try {
                textToDecrypt = p.Parse(args).FirstOrDefault();
                if (textToDecrypt == null && fileToDecrypt != null)
                {
                    if (!File.Exists(fileToDecrypt))
                        throw new OptionException("input file does not exist", "input");
                    textToDecrypt = File.ReadAllText(fileToDecrypt);
                }

            }
            catch (OptionException ex) {
                Console.Error.Write("ERROR: invalid argument, ");
                Console.Error.WriteLine(ex.Message);
                Console.Error.WriteLine();
                showhelp = true;
            } 
            if (!showhelp && textToDecrypt == null) {
                Console.Error.WriteLine("ERROR: please provide data to decrypt");
                Console.Error.WriteLine();
                showhelp = true;
            }
            if (!showhelp && (validationKeyAsText == null || decryptionKeyAsText == null || purposeKey == null)) {
                Console.Error.WriteLine("ERROR: all parameters are required");
                Console.Error.WriteLine();
                showhelp = true;
            }
            Purpose purpose = null;
            if (!showhelp && !purposeMap.TryGetValue(purposeKey, out purpose)) {
                Console.Error.WriteLine("ERROR: invalid purpose");
                Console.Error.WriteLine();
                showhelp = true;
            }
            if (showhelp) {
                ShowHelp(p);
                return;
            }
            Debug.Assert(purpose != null);
            Debug.Assert(textToDecrypt != null);
            Debug.Assert(decryptionKeyAsText != null);
            Debug.Assert(validationKeyAsText != null);

            byte[] encryptedData;
            if (isBase64) {
                try {
                    encryptedData = HttpEncoder.Default.UrlTokenDecode(textToDecrypt);
                } catch (FormatException) {
                    encryptedData = null;
                }
            } else {
                if (textToDecrypt.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) {
                    textToDecrypt = textToDecrypt.Substring(2);
                }
                encryptedData = CryptoUtil.HexToBinary(textToDecrypt);
            }
            byte[] decryptionKey = CryptoUtil.HexToBinary(decryptionKeyAsText.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ?
                decryptionKeyAsText.Substring(2) : decryptionKeyAsText);
            byte[] validationKey = CryptoUtil.HexToBinary(validationKeyAsText.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ?
                validationKeyAsText.Substring(2) : validationKeyAsText);
            if (decryptionKey == null || validationKey == null) {
                Console.Error.WriteLine("ERROR: invalid encryption or validation key");
                Console.Error.WriteLine();
                return;
            }

            if (encryptedData == null) {
                Console.Error.WriteLine("ERROR: invalid data to decrypt - must be either base64 or hex");
                Console.Error.WriteLine();
                return;
            }

            Console.WriteLine();
            var decryptor = new AspNetDecryptor(purpose, new CryptographicKey(decryptionKey), new CryptographicKey(validationKey), 
                "owin.cookie".Equals(purposeKey, StringComparison.Ordinal));
            var decryptedData = decryptor.DecryptData(encryptedData);
            Console.WriteLine(Hexify.Hex.PrettyPrint(decryptedData));
            Console.WriteLine();

            if ("forms.cookie".Equals(purposeKey, StringComparison.Ordinal))
            {
                WriteFormsAuthenticadtionTicket(decryptedData);
            }
        }

        static void WriteFormsAuthenticadtionTicket(byte[] data)
        {
            var ticket = FormsAuthenticationTicketSerializer.Deserialize(data, data.Length);
            Console.WriteLine("Name: {0}", ticket.Name);
            Console.WriteLine("UserData: {0}", ticket.UserData);
            Console.WriteLine("CookiePath: {0}", ticket.CookiePath);
            Console.WriteLine("IssueDate: {0}", ticket.IssueDate);
            Console.WriteLine("IssueDateUtc: {0}", ticket.IssueDateUtc);
            Console.WriteLine("Expiration: {0}", ticket.Expiration);
            Console.WriteLine("ExpirationUtc: {0}", ticket.ExpirationUtc);
            Console.WriteLine("Expired: {0}", ticket.Expired);
            Console.WriteLine("IsPersistent: {0}", ticket.IsPersistent);
            Console.WriteLine("Version: {0}", ticket.Version);
        }

        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("{0} v{1} - {2}", Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyTitleAttribute>().Title,
                Assembly.GetExecutingAssembly().GetName().Version.ToString(), 
                Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyDescriptionAttribute>().Description);
            Console.WriteLine(Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyCopyrightAttribute>().Copyright);
            Console.WriteLine();
            Console.WriteLine("Usage: aspnetcrypter [OPTIONS] encrypteddata");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
            Console.WriteLine();
        }
    }
}
