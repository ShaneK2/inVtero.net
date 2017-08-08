using Microsoft.Azure;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Table;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace inVtero.net.Hashing
{
    public class CloudDB
    {
        public class HashEntity : TableEntity
        {
            public HashEntity() { }
            public HashEntity(HashRec rec)
            {
                Hash = rec;

                PartitionKey = $"{rec.FullHash[0].ToString("x")}";
                RowKey = BitConverter.ToString(rec.FullHash, 1).Replace("-", "").ToLower();
                MetaInfo = rec.RID.ToString();
            }

            public string MetaInfo { get; set; }

            public bool FoundInDB;
            public HashRec Hash;
        }

        /// <summary>
        /// use this if you want to specify connection strings in the app config...
        /// I've hard coded an Azure Table SAS key for use in the code so...
        /// </summary>
        /// <param name="storageConnectionString"></param>
        /// <returns></returns>
        public static CloudStorageAccount CreateStorageAccountFromConnectionString(string storageConnectionString)
        {
            CloudStorageAccount storageAccount;
            try
            {
                storageAccount = CloudStorageAccount.Parse(storageConnectionString);
            }
            catch (FormatException)
            {
                Console.WriteLine("Invalid storage account information provided. Please confirm the AccountName and AccountKey are valid in the app.config file - then restart the application.");
                throw;
            }
            catch (ArgumentException)
            {
                Console.WriteLine("Invalid storage account information provided. Please confirm the AccountName and AccountKey are valid in the app.config file.");
                Console.ReadLine();
                throw;
            }
            return storageAccount;
        }

        /// <summary>
        /// This has a read only SAS key embedded for a cloud hosted table provided by your's truely
        /// Right now it's only 4k and 256byte blocks for Windows default install updated Aug-2017 1703 edition of Win 10
        /// </summary>
        /// <param name="TableName"></param>
        /// <returns></returns>
        public static CloudTable AccessTable(string TableName)
        {
            ServicePointManager.UseNagleAlgorithm = false;
            ServicePointManager.CheckCertificateRevocationList = false;
            ServicePointManager.Expect100Continue = false;
            ServicePointManager.ReusePort = true;

            var endPoint = new Uri("https://invtero.table.core.windows.net/?sv=2016-05-31&ss=t&srt=sco&sp=rl&se=2018-08-04T20:35:06Z&st=2017-08-04T12:35:06Z&spr=https&sig=LS%2Fe7zpixUdKP1DjcT%2FOaUtFOQuDQ%2FZNVseBu3kJYgk%3D");
            CloudTable rv = new CloudTable(endPoint);

            var tableClient = rv.ServiceClient;

            tableClient.DefaultRequestOptions.PayloadFormat = TablePayloadFormat.JsonNoMetadata;
            tableClient.DefaultRequestOptions.RequireEncryption = false;
            tableClient.DefaultRequestOptions.MaximumExecutionTime = new TimeSpan(0, 30, 0);
            tableClient.DefaultRequestOptions.ServerTimeout = new TimeSpan(0, 30, 0);

            var tableServicePoint = ServicePointManager.FindServicePoint(endPoint);
            tableServicePoint.UseNagleAlgorithm = false;
            tableServicePoint.ConnectionLimit = 1024;
            tableServicePoint.MaxIdleTime = int.MaxValue;
            tableServicePoint.ConnectionLeaseTimeout = int.MaxValue;
            tableServicePoint.Expect100Continue = false;

            return tableClient.GetTableReference(TableName);
        }

        /// <summary>
        /// If you're going to create your own table's in Azure, Create Table 
        /// </summary>
        /// <param name="tableName"></param>
        /// <returns></returns>
        public static CloudTable CreateTable(string tableName)
        {
            ServicePointManager.UseNagleAlgorithm = false;
            var storageAccount = CreateStorageAccountFromConnectionString(CloudConfigurationManager.GetSetting("StorageConnectionString"));

            // Create a table client for interacting with the table service
            var tableClient = storageAccount.CreateCloudTableClient();

            tableClient.DefaultRequestOptions.PayloadFormat = TablePayloadFormat.JsonNoMetadata;
            tableClient.DefaultRequestOptions.RequireEncryption = false;
            tableClient.DefaultRequestOptions.MaximumExecutionTime = new TimeSpan(0, 30, 0);
            tableClient.DefaultRequestOptions.ServerTimeout = new TimeSpan(0, 30, 0);
            
            var tableServicePoint = ServicePointManager.FindServicePoint(storageAccount.TableEndpoint);
            tableServicePoint.UseNagleAlgorithm = false;
            tableServicePoint.ConnectionLimit = 1024;
            tableServicePoint.MaxIdleTime = int.MaxValue;
            tableServicePoint.ConnectionLeaseTimeout = int.MaxValue;
            tableServicePoint.Expect100Continue = false;

            // Create a table client for interacting with the table service 
            var table = tableClient.GetTableReference(tableName);
            try
            {
                table.CreateIfNotExists();
            }
            catch (StorageException)
            {
                Console.WriteLine("Can not connect to Azure.");
                throw;
            }
            return table;
        }
    }
}
