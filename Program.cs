using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security;
using System.Threading.Tasks;

namespace GetSPORefreshToken
{
    class Program
    {
        
        static async Task Main(string[] args)
        {
            Console.WriteLine("Enter the Client Id (eg. ba453a4e-486e-4815-aad5-16b724e99a2b):");
            Console.Write("> ");
            string clientId = Console.ReadLine();
            if (string.IsNullOrEmpty(clientId))
            {
                Console.WriteLine("The Client Id is required.");
                return;
            }

            Console.WriteLine("Enter the Client Secret:");
            Console.Write("> ");
            SecureString clientSecret = ReadSecureString();

            Console.WriteLine("Enter the Tenant Id (eg. 84ccd87e-0dff-4bd8-b183-f5d89e415a71):");
            Console.Write("> ");
            string tenantId = Console.ReadLine();
            if (string.IsNullOrEmpty(tenantId))
            {
                Console.WriteLine("The Tenant Id is required.");
                return;
            }

            Console.WriteLine("Enter the SharePoint Online Domain (ie. contoso.sharepoint.com):");
            Console.Write("> ");
            string spoDomain = Console.ReadLine();
            if (string.IsNullOrEmpty(spoDomain))
            {
                Console.WriteLine("The SharePoint Online Domain is required.");
                return;
            }

            Console.WriteLine("Enter the Redirect URL or press enter to accept the default (https://localhost):");
            Console.Write("> ");
            string redirectUrl = Console.ReadLine();
            if (string.IsNullOrEmpty(redirectUrl))
            {
                redirectUrl = "https://localhost";
            }

            Console.WriteLine("Enter the Authentication Code:");
            Console.Write("> ");
            SecureString authCode = ReadSecureString();

            using (var httpClient = new HttpClient())
            {
                var tokenRequestUrl = $"https://accounts.accesscontrol.windows.net/{tenantId}/tokens/OAuth/2";
                var bodyValues = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                    new KeyValuePair<string, string>("client_id", $"{clientId}@{tenantId}"),
                    new KeyValuePair<string, string>("client_secret", MarshalPtrToStringSecureString(clientSecret)),
                    new KeyValuePair<string, string>("code", MarshalPtrToStringSecureString(authCode)),
                    new KeyValuePair<string, string>("redirect_uri", redirectUrl),
                    new KeyValuePair<string, string>("resource", $"00000003-0000-0ff1-ce00-000000000000/{spoDomain}@{tenantId}")
                };

                try
                {
                    var response = await httpClient.PostAsync(tokenRequestUrl, new FormUrlEncodedContent(bodyValues));
                    response.EnsureSuccessStatusCode();
                    var responseContent = await response.Content.ReadAsStringAsync();

                    // Parse the JSON response using Newtonsoft.Json
                    var tokenResponse = JsonConvert.DeserializeObject<TokenResponse>(responseContent);

                    if (tokenResponse != null && !string.IsNullOrEmpty(tokenResponse.refresh_token))
                    {
                        Console.WriteLine($"The Refresh Token is: {tokenResponse.refresh_token}");
                    }
                    else
                    {
                        Console.WriteLine("Refresh token not found in the response.");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
                Console.ReadKey();
            }
        }

        private class TokenResponse
        {
            public string refresh_token { get; set; }
        }

        private static SecureString ReadSecureString()
        {
            SecureString secureString = new SecureString();
            while (true)
            {
                ConsoleKeyInfo key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter)
                {
                    break;
                }
                else if (key.Key == ConsoleKey.Backspace)
                {
                    if (secureString.Length > 0)
                    {
                        secureString.RemoveAt(secureString.Length - 1);
                        Console.Write("\b \b");
                    }
                }
                else
                {
                    secureString.AppendChar(key.KeyChar);
                    Console.Write("*");
                }
            }
            Console.WriteLine();
            secureString.MakeReadOnly();
            return secureString;
        }

        private static string MarshalPtrToStringSecureString(SecureString secureString)
        {
            IntPtr ptr = IntPtr.Zero;
            try
            {
                ptr = Marshal.SecureStringToGlobalAllocUnicode(secureString);
                return Marshal.PtrToStringUni(ptr);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(ptr);
            }
        }
    }
}
