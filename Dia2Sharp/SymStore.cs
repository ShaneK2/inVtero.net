using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net;
using System.IO.Compression;

namespace Dia2Sharp
{
    public class SymStore
    {
        const string SymSrv = "https://msdl.microsoft.com/download/symbols/"; 
        // ntkrnlmp.pdb/F6F4895554894B24B4DF942361F0730D1/ntkrnlmp.pdb
        // ntoskrnl.exe/597fd80d889000/ntoskrnl.exe
        public string SymFolder;
        public SymStore(string folder)
        {
            SymFolder = folder;
            if (!Directory.Exists(SymFolder))
                Directory.CreateDirectory(SymFolder);
        }

        public async void GetSymbolFile(CODEVIEW_HEADER cvh, Stream rstrm)
        {
            var uri = $"{SymSrv}{cvh.PdbName}/{cvh.aGuid:N}{cvh.Age:X1}/{cvh.PdbName}";

            var dl = new SymDownloader();



            var request = WebRequest.Create(uri) as HttpWebRequest;
            request.UserAgent = UserAgent;
            request.Headers[HttpRequestHeader.AcceptEncoding] = "gzip, deflate";
            Task<HttpWebResponse> response = null;
            try
            {
                using (var resp = await request.GetResponseAsync())
                {
                    using (var str = resp.GetResponseStream())
                    using (var gsr = new GZipStream(str, CompressionMode.Decompress))
                    using (var sr = new StreamReader(gsr))
                        await sr.BaseStream.CopyToAsync(rstrm);
                }
            } catch(Exception ex) { }

            if (response == null || response.StatusCode != HttpStatusCode.OK)
            {
                uri = $"{SymSrv}{cvh.PdbName}/{cvh.aGuid:N}{cvh.Age:X1}/{cvh.PdbName.Substring(0, cvh.PdbName.Length - 1)}_";

                request = WebRequest.Create(uri) as HttpWebRequest;
                request.UserAgent = UserAgent;

                try
                {
                    using (var resp = await request.GetResponseAsync())
                    {
                        using (var str = resp.GetResponseStream())
                        using (var gsr = new GZipStream(str, CompressionMode.Decompress))
                        using (var sr = new StreamReader(gsr))
                            await sr.BaseStream.CopyToAsync(rstrm);
                    }
                }
                catch (Exception ex) { }
            }
            if (response == null || response.StatusCode != HttpStatusCode.OK)
                return;

            using (Stream responseStream = request.GetResponseAsync())
            {
                var buffer = new byte[4096];
                long totalBytesRead = 0;
                int bytesRead;

                while ((bytesRead = responseStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    totalBytesRead += bytesRead;
                    rstrm.Write(buffer, 0, bytesRead);
                }
            }
        }
        public string GetBinary(CODEVIEW_HEADER cvh)
        {
            return string.Empty;
        }
    }
}
