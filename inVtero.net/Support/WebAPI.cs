using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using static inVtero.net.Misc;

namespace inVtero.net.Support
{
    public class WebAPI
    {
        // Returns JSON string
        public static string GET(string queryStr = null, string url = "https://invterocheck.azurewebsites.net/api/check/")
        {
            var request = (HttpWebRequest)WebRequest.Create($"{url}{queryStr}");
            try {
                var response = request.GetResponse();
                using (var responseStream = response.GetResponseStream())
                {
                    var reader = new StreamReader(responseStream, Encoding.UTF8);
                    return reader.ReadToEnd();
                }
            }
            catch (WebException ex)
            {
                var errorResponse = ex.Response;
                using (var responseStream = errorResponse.GetResponseStream())
                {
                    var reader = new StreamReader(responseStream, Encoding.GetEncoding("utf-8"));
                    var errorText = reader.ReadToEnd();
                    WriteColor(ConsoleColor.Yellow, $"error with server get. {errorText} {ex.ToString()}");
                }
                throw;
            }
        }

         
        public static string POST(string paramz = null, string url = "https://invterocheck.azurewebsites.net/api/check/hash")
        {
            var request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "POST";

            var encoding = new UTF8Encoding();
            var byteArray = encoding.GetBytes(paramz);

            request.ContentLength = byteArray.Length;
            request.ContentType = @"application/json";

            using (var dataStream = request.GetRequestStream())
                dataStream.Write(byteArray, 0, byteArray.Length);
            
            long length = 0;
            using (var response = (HttpWebResponse)request.GetResponse())
            {
                length = response.ContentLength;
                using (var responseStream = response.GetResponseStream())
                {
                    var reader = new StreamReader(responseStream, Encoding.UTF8);
                    return reader.ReadToEnd();
                }
            }
            return string.Empty;
        } 
    }
}
