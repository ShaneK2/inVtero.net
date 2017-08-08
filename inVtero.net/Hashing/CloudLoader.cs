using Microsoft.WindowsAzure.Storage.Table;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Algorithms;
using System.Threading.Tasks;
using static inVtero.net.Misc;
using static inVtero.net.CompareHelp;
using System.Collections.Concurrent;
using System.Threading;
using static inVtero.net.Hashing.CloudDB;
using Microsoft.WindowsAzure.Storage;
using Reloc;
using System.IO;
using static inVtero.net.MagicNumbers;
using System.Net;
using System.Net.Sockets;
using inVtero.net.Support;
//using Newtonsoft.Json;
//using Newtonsoft.Json.Linq;

namespace inVtero.net.Hashing
{
    /// <summary>
    /// Initial implmentation of a set of Azure services.
    /// Azure Table Service and/or Azure Function 
    /// The Table Service is a traditional cloud NoSQL DB.  Here are interfaces to load/query it.
    /// 
    /// The REST API is currently implmented as an Azure Function.  Server implmentation code to be released soon.
    /// </summary>
    public class CloudLoader
    {
        public int MaxBatchParallel { get; set; }
        public string InfoString { get; set; }

        int MinHashSize;
        long TotalRequested =0;
        long TotalUpdated = 0;
        FileLoader FL;
        CloudTable QueryTable;

        public CloudLoader()
        {
            MaxBatchParallel = 8;
            ServicePointManager.DefaultConnectionLimit = 512;
            ServicePointManager.CheckCertificateRevocationList = false;
            ServicePointManager.Expect100Continue = false;
            ServicePointManager.ReusePort = true;
            ThreadPool.SetMinThreads(256, 256);
        }

        public CloudLoader(FileLoader fl, int BlockSize) :this()
        {
            FL = fl;
            MinHashSize = BlockSize;
        }

        CloudTable GetTable(int BlockSize)
        {
            CloudTable table = null;

            if (BlockSize == 4096)
                table = CreateTable($"hash4k");
            else 
                table = CreateTable($"hash{BlockSize}");

            return table;
        }

        string InitialScanFolder;
        bool DoneDirScan, DoneDump;
        Stopwatch GeneratedSW, UploadedSW;
        CancellationTokenSource source;
        Func<HashLib.IHash> GetHP;

        BlockingCollection<List<HashRec>> ReadyQueue;
        List<HashRec>[] batches;

        public void LoadFromPath(string Folder)
        {
            // read/write table
            QueryTable = GetTable(MinHashSize);
            InitialScanFolder = Folder;
            ReadyQueue = new BlockingCollection<List<HashRec>>();


            source = new CancellationTokenSource();
            FL.source = source;

            batches = new List<HashRec>[256];
            for (int i = 0; i < 256; i++)
                batches[i] = new List<HashRec>();

            source.Token.Register(() => WriteColor(ConsoleColor.Red, $"Cancelation requested. {FL.LoadExceptions.Count} file load exceptions occured."), true);
            CancellationToken token = source.Token;

            try
            {
                var po = new ParallelOptions() { CancellationToken = token, MaxDegreeOfParallelism = MaxBatchParallel };

                Parallel.Invoke((po),
                    () =>
                    {
                        FL.GenerateSW = Stopwatch.StartNew();

                        FL.RecursiveGenerate(Folder, po);
                        DoneDirScan = true;
                        WriteColor(ConsoleColor.Green, $"Finished FS load from {Folder} task time: {FL.GenerateSW.Elapsed}");
                    },
                    () =>
                    {
                        DumpToCloud(po);
                        DoneDump = true;
                    },
                    () =>
                    {
                        UploadedSW = Stopwatch.StartNew();
                        var po2 = new ParallelOptions() { MaxDegreeOfParallelism = MaxBatchParallel };
                        do
                        {
                            Parallel.ForEach(ReadyQueue.GetConsumingEnumerable(token), po2, (recs) => {

                                BatchBatch(QueryTable, recs, BatchInsert);

                            });
                        } while (!DoneDump || !ReadyQueue.IsCompleted);
                    }
                );
            }
            catch (AggregateException agg)
            {
                WriteColor(ConsoleColor.Yellow, $"AggregateException: {agg.ToString()} InnerException {agg.InnerException.ToString()}");
                source.Cancel();
            }
            WriteColor(ConsoleColor.Cyan, $"Total uploaded {TotalUpdated}, TotalRequested {TotalRequested}");
            WriteColor(ConsoleColor.White, $"Total task runtime: {FL.GenerateSW.Elapsed}. {TotalUpdated/UploadedSW.Elapsed.TotalSeconds} per second");
            ReadyQueue.Dispose();
        }

        /// <summary>
        /// This REST query is for a hosted Azure Functions application that allows batch queries :)
        /// </summary>
        /// <param name="hashArr"></param>
        public void QueryREST(HashRecord[] hashArr)
        {
            int Count = hashArr.Length;
            var rv = new List<bool>(Count);

            //for (int i = 0; i < hashArr.Length; i++)
            //{
            Parallel.For(0, hashArr.Length, (i) =>
            {
                var hashModule = hashArr[i];
                for (int l = 0; l < hashModule.Regions.Count; l++)
                {
                    var hashRegion = hashArr[i].Regions[l];
                    var sb = new StringBuilder();

                    for (int m = 0; m < hashRegion.InnerList.Count; m++)
                    {
                        var CheckHashes = hashArr[i].Regions[l].InnerList[m];

                        foreach (var ch in CheckHashes)
                            sb.Append($"{(ch.Index >> HASH_SHIFT):x},");
                    }

                    var results = WebAPI.POST(sb.ToString());
                    //var jr = JObject.Parse(results);
                    //var ValidArr = from v in jr["HashResults"]["Valid"]
                    //select v.ToArray();
                    for (int m = 0; m < hashRegion.InnerList.Count; m++)
                    {
                        var CheckHashes = hashArr[i].Regions[l].InnerList[m];

                        var checkedArr = new bool[CheckHashes.Length];
                        for (int ch = 0; ch < CheckHashes.Length; ch++)
                        {
                            if (results.Contains((CheckHashes[ch].Index >> HASH_SHIFT).ToString("x")))
                                checkedArr[ch] = true;
                        }

                        hashRegion.InnerCheckList.Add(checkedArr);
                        hashRegion.Total += checkedArr.Length;

                        // update aggrogate counters
                        for (int n = 0; n < checkedArr.Length; n++)
                        {
                            if (checkedArr[n])
                                hashArr[i].Regions[l].Validated++;
                            else
                                hashArr[i].Regions[l].Failed++;
                        }
                    }
                    //}

                }
            });
            return;
        }

        /// <summary>
        /// Query a hosted Azure Table Service
        /// </summary>
        /// <param name="hashArr"></param>
        public void QueryHashes(HashRecord[] hashArr)
        {
            ParallelOptions po = new ParallelOptions();
            po.MaxDegreeOfParallelism = MaxBatchParallel;

            var name = $"hash{MinHashSize}";
            if (MinHashSize == 4096)
                name = $"hash4k";

            QueryTable = AccessTable(name);

            ReadyQueue = new BlockingCollection<List<HashRec>>();

            #region CanNotBatchContains

            //var items = (from ha in hashArr
            //              from agg in ha.GetAllRecs()
            //              select agg).ToArray();

            //Parallel.Invoke(() =>
            //{

            //    // group into 100 count batches
            //    batches = new List<HashRec>[256];
            //    for (int i = 0; i < 256; i++)
            //        batches[i] = new List<HashRec>();

            //    List<HashRec> batch = null;

            //    foreach (var item in items)
            //    {
            //        batch = batches[item.FullHash[0]];

            //        bool contains = batch.Any(x => x.FullHash.SequenceEqual(item.FullHash));

            //        if (contains) continue;

            //        batch.Add(item);
            //        if (batch.Count == 100)
            //        {
            //            // signal uploader
            //            ReadyQueue.Add(batch);

            //            // reset batch
            //            batch = new List<HashRec>();
            //            batches[item.FullHash[0]] = batch;
            //        }
            //    }
            //    foreach (var b in batches)
            //    {
            //        if (b.Count < 1)
            //            continue;

            //        ReadyQueue.Add(b);
            //    }
            //    ReadyQueue.CompleteAdding();
            //}, () =>
            //{
            //    var po2 = new ParallelOptions() { MaxDegreeOfParallelism = MaxBatchParallel };
            //    do
            //    {
            //        Parallel.ForEach(ReadyQueue.GetConsumingEnumerable(), po2, (recs) => {
            //            var readIn = BatchBatch(QueryTable, recs, BatchContains);
            //            foreach(var rec in readIn)
            //            {
            //                if(rec.FoundInDB)
            //                {
            //                    for (int i = 0; i < items.Length; i++)
            //                    {
            //                        if (items[i].FullHash == rec.Hash.FullHash)
            //                        {
            //                            items[i].Verified = true;
            //                            break;
            //                        }
            //                    }
            //                }
            //            }
            //        });
            //    } while (!DoneDump || !ReadyQueue.IsCompleted);
            //});

            //foreach (var hr in hashArr)
            //    hr.AssignRecResults(items);
            #endregion
            #region old
            int Count = hashArr.Length;
            var rv = new List<bool>(Count);
            //for (int i = 0; i < hashArr.Length; i++)
            //{
            Parallel.ForEach(hashArr, po, (hashModule) =>
            {
                //var hashModule = hashArr[i];
                for (int l = 0; l < hashModule.Regions.Count; l++)
                {
                    var hashRegion = hashModule.Regions[l];
                    Parallel.ForEach(hashRegion.InnerList, po, (il) =>
                    {
                    //foreach (var il in hashRegion.InnerList)
                    //{
                        for (int m = 0; m < il.Length; m++)
                        {
                            var check = il[m];

                            if (Contains(QueryTable, new HashEntity(check)))
                                Interlocked.Increment(ref hashModule.Regions[l].Validated);
                            else
                                Interlocked.Increment(ref hashModule.Regions[l].Failed);

                            Interlocked.Increment(ref hashRegion.Total);
                        }
                    //}
                    });
                }
            });
        #endregion
        ReadyQueue.Dispose();
        return;
        }

        private List<HashEntity> BatchBatch(CloudTable table, List<HashRec> recs, Func<CloudTable, HashEntity[], IList<TableResult>> BatchOp)
        {
            List<HashEntity> all = new List<HashEntity>();
            // if were still loading keep waiting till the buckets are all full
            List<HashEntity> entities = new List<HashEntity>();
            for (int h = 0; h < recs.Count; h++)
            {
                var e = new HashEntity(recs[h]);
                e.MetaInfo = $"{recs[h].RID}";
                entities.Add(e);

                if (entities.Count == 100)
                {
                    BatchOp(table, entities.ToArray());
                    
                    all.AddRange(entities);
                    entities = new List<HashEntity>();
                }
            }
            if (entities.Count > 0)
                BatchOp(table, entities.ToArray());

            return all;
        }

        /// <summary>
        /// Azure Table service Batch mode inserts
        /// </summary>
        /// <param name="table"></param>
        /// <param name="entries"></param>
        /// <returns></returns>
        private IList<TableResult> BatchInsert(CloudTable table, HashEntity[] entries)
        {
            bool KeepTrying = false;
            int retryCount = 10;

            // Create the batch operation. 
            TableBatchOperation batchOperation = new TableBatchOperation();
            
            // The following code  generates test data for use during the query samples.  
            foreach (var entry in entries)
                batchOperation.InsertOrReplace(entry);

            IList<TableResult> results = null;
            // Execute the batch operation.
            do { try {
                    results = table.ExecuteBatch(batchOperation);
                } catch (SocketException se) {
                    KeepTrying = true;
                    retryCount--;
                    if (retryCount <= 0)
                        KeepTrying = false;
                } } while (KeepTrying == true);


            Interlocked.Add(ref TotalUpdated, results.Count);
            if ((TotalUpdated % 1000) == 0)
                WriteColor(ConsoleColor.Cyan, $"DB write {TotalUpdated:N0} entries. {(TotalUpdated)/UploadedSW.Elapsed.TotalSeconds} per second. Task time: {UploadedSW.Elapsed}");

            return results;
        }

        /// <summary>
        /// Contains uses Azure Table services (one at a time, threaded, no batching here)
        /// </summary>
        /// <param name="table"></param>
        /// <param name="check"></param>
        /// <returns></returns>
        private bool Contains(CloudTable table, HashEntity check)
        {
            bool KeepTrying = false;
            int retryCount = 10;
            TableResult result = null;
            HashEntity entry = null;

            TableOperation retrieveOperation = TableOperation.Retrieve<HashEntity>(check.PartitionKey, check.RowKey);

            do { try {
                    result = table.Execute(retrieveOperation);
                } catch (SocketException se) {
                    KeepTrying = true;
                    retryCount--;
                    if (retryCount <= 0)
                        KeepTrying = false;
            } } while (KeepTrying == true);

            entry = result.Result as HashEntity;
            if (entry != null)
                return true;
            return false;
        }

        // batching is not supported for query unless you do a range query
#if FALSE
        private IList<TableResult> BatchContains(CloudTable table, HashEntity[] entries)
        {
            // Create the batch operation. 
            TableBatchOperation batchOperation = new TableBatchOperation();
            
            // The following code  generates test data for use during the query samples.  
            foreach (var entry in entries)
                batchOperation.Retrieve<HashEntity>(entry.PartitionKey, entry.RowKey);

            // Execute the batch operation.
            IList<TableResult> results = table.ExecuteBatch(batchOperation);
            foreach (var result in results)
            {
                var r = result.Result as HashEntity;
                if (r == null)
                    continue;

                // propagate info to outer collection
                var entry = entries.First(x => x.RowKey.SequenceEqual(r.RowKey));
                entry.FoundInDB = true;
            }

            Interlocked.Add(ref TotalUpdated, results.Count);
            if ((TotalUpdated % 1000) == 0)
                WriteColor(ConsoleColor.Cyan, $"DB read {TotalUpdated:N0} entries. {(TotalUpdated) / UploadedSW.Elapsed.TotalSeconds} per second. Task time: {UploadedSW.Elapsed}");

            return results;
        }
#endif
        public void DumpToCloud(ParallelOptions po)
        {
            long TotalDBWrites = 0;
            Extract hashFile = null;
            List<HashRec> batch = null;

            if (GetHP == null)
                GetHP = new Func<HashLib.IHash>(() => { return HashLib.HashFactory.Crypto.CreateTiger2(); });

            GeneratedSW = Stopwatch.StartNew();
            while (!DoneDirScan || FL.LoadList.Count > 0)
            {
                FL.LoadList.TryPop(out hashFile);
                if (hashFile == null && !DoneDirScan)
                {
                    if (po.CancellationToken.IsCancellationRequested) return;
                    Thread.Yield();
                    continue;
                }

                if (po.CancellationToken.IsCancellationRequested) return;

                foreach (var ms in hashFile.Sections)
                {
                    // ONLY hash CODE/EXEC file sections & PEHeader
                    if (!ms.IsCode && !ms.IsExec)
                        continue;

                    var ReadSize = ms.VirtualSize;
                    var BufferSize = (int)((ReadSize + 0xfff) & ~0xfff);
                    var memBuff = new byte[BufferSize];

                    using (var fread = new FileStream(hashFile.FileName, FileMode.Open, FileAccess.Read, FileShare.Read, PAGE_SIZE))
                    {
                        fread.Seek(ms.RawFilePointer, SeekOrigin.Begin);
                        fread.Read(memBuff, 0, (int)ReadSize);
                    }

                    foreach (var items in FractHashTree.CreateRecsFromMemoryPartion(memBuff, MinHashSize, GetHP, hashFile.rID))
                    {
                        if (items == null)
                            continue;

                        foreach (var item in items)
                        {
                            batch = batches[item.FullHash[0]];

                            bool contains = batch.Any(x => x.FullHash.SequenceEqual(item.FullHash));

                            if (contains) continue;

                            batch.Add(item);

                            Interlocked.Increment(ref TotalRequested);

                            if (batch.Count == 100)
                            {
                                Interlocked.Add(ref TotalDBWrites, batch.Count);

                                if ((TotalRequested % 100) == 0)
                                    WriteColor(ConsoleColor.Green, $"Generated {TotalDBWrites:N0} entries {(TotalDBWrites/ GeneratedSW.Elapsed.TotalSeconds):N0} per second. Task time: {GeneratedSW.Elapsed}");

                                // signal uploader
                                ReadyQueue.Add(batch);

                                // reset batch
                                batch = new List<HashRec>();
                                batches[item.FullHash[0]] = batch;
                            }
                        }
                    }
                }
            }
            foreach (var b in batches)
            {
                if (b.Count < 1)
                    continue;

                ReadyQueue.Add(b);
                TotalDBWrites += b.Count;
            }
            ReadyQueue.CompleteAdding();
            WriteColor(ConsoleColor.Green, $"Finished DB write {TotalDBWrites:N0} NEW entries. Requsted {TotalRequested:N0} (reduced count reflects de-duplication). Task time: {GeneratedSW.Elapsed}");
        }
    }
}
