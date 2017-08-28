using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using static inVtero.net.Misc;

namespace inVtero.net.Support
{
    public static class WebAPI
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
                if (ex.Response != null)
                {
                    var errorResponse = ex.Response;
                    using (var responseStream = errorResponse.GetResponseStream())
                    {
                        var reader = new StreamReader(responseStream, Encoding.GetEncoding("utf-8"));
                        var errorText = reader.ReadToEnd();
                        if(Vtero.VerboseLevel > 1)
                            WriteColor(ConsoleColor.Yellow, $"error with server get. {errorText} {ex.ToString()}");
                    }
                } else
                    if (Vtero.VerboseLevel > 2)
                        WriteColor(ConsoleColor.Yellow, $"error connecting to server {url}{queryStr} exception [{ex.ToString()}]");
            }
            return string.Empty;
        }

        public static void TryStreamDownload(string aURI, Stream aWriteLocation)
        {
            var request = WebRequest.Create(aURI) as HttpWebRequest;
            try
            {
                using (var resp = request.GetResponse())
                {
                    using (var str = resp.GetResponseStream())
                    {
                        byte[] buffer = new byte[1024];
                        int size = str.Read(buffer, 0, buffer.Length);
                        while (size > 0)
                        {
                            aWriteLocation.Write(buffer, 0, size);
                            size = str.Read(buffer, 0, buffer.Length);
                        }
                        aWriteLocation.Flush();
                    }
                }
            }
            catch (Exception ex) {
                WriteColor(ConsoleColor.Yellow, $"error with server get. {ex.ToString()}");
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
        }
    }

    /// https://invtero.blob.core.windows.net/relocs64?restype=container&comp=list&prefix=IPHLPAPI.DLL&include=metadata7

    public class RestBlobClient
    {
        string aUri;

        string Options = "?restype=container&comp=list&include=metadata&prefix=";
        public RestBlobClient(string auri = "https://invtero.blob.core.windows.net/")
        {
            aUri = auri;
        }

        /// <summary>
        /// List blobs in the Azure container
        /// </summary>
        /// <param name="Prefix">{ContainerName}/{ItemPrefix}</param>
        /// <param name="UseFlat"></param>
        /// <param name="ListMetaData"></param>
        /// <returns></returns>
        public IEnumerable<RestBlobClient> ListBlobs(string Prefix, bool UseFlat = true, bool ListMetaData = true)
        {
            var splitName = Prefix.Split('/');

            if(splitName.Length != 2)
                throw new FormatException("Input should be in format of CONTAINER/FileNamePrefix (there is a forward slash in the middle '/')");

            var containerName = splitName[0];
            var filePrefix = splitName[1];

            var rv = new List<RestBlobClient>();

            // make the web services call and load up the metadata
            // Ensure DownloadToStream can be called...
            var Xresponse = WebAPI.GET(null, $"{aUri}{containerName}{Options}{filePrefix}");

            var x = XElement.Parse(Xresponse);
            var blobs = x.Element("Blobs");
            foreach (var b in blobs.Elements())
            {
                var blobUrl = b.Element("Url").Value;
                var result = new RestBlobClient(blobUrl);
                foreach (var md in b.Element("Metadata").Elements())
                    result.Metadata.Add(md.Name.ToString(), md.Value);

                rv.Add(result);
            }

            return rv;
        }

        public Dictionary<String, String> Metadata = new Dictionary<string, string>();

        public void DownloadToStream(Stream stream)
        {
            WebAPI.TryStreamDownload(aUri, stream);
        }
    }
}
