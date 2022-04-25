" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

if version < 600
    syntax clear
elseif exists("b:current_syntax")
    finish
endif

setlocal iskeyword+=.
setlocal iskeyword+=:
setlocal iskeyword+=-

syn case match

syn match confComment /^#.*/ contains=confTodo oneline display
syn match confSpecComment /^\s.*/ contains=confTodo oneline display
syn match confSpecComment /^\*.*/ contains=confTodo oneline display

syn region confString start=/"/ skip="\\\"" end=/"/ oneline display contains=confNumber,confVar
syn region confString start=/`/             end=/`/ oneline display contains=confNumber,confVar
syn region confString start=/'/ skip="\\'"  end=/'/ oneline display contains=confNumber,confVar
syn match  confNumber /\v[+-]?\d+([ywdhsm]|m(on|ins?))(\@([ywdhs]|m(on|ins?))\d*)?>/
syn match  confNumber /\v[+-]?\d+(\.\d+)*>/
syn match  confNumber /\v<\d+[TGMK]B>/
syn match  confNumber /\v<\d+(k)?b>/
syn match  confPath   ,\v(^|\s|\=)\zs(file:|https?:|hdfs:|\$\k+)?(/+\k+)+(:\d+)?,
syn match  confPath   ,\v(^|\s|\=)\zsvolume:\k+(/+\k+)+,
syn match  confVar    /\$\k\+\$/

syn keyword confBoolean on off t[rue] f[alse] T[rue] F[alse]
syn keyword confTodo FIXME[:] NOTE[:] TODO[:] CAUTION[:] contained

" Define generic stanzas
syn match confGenericStanzas display contained /\v[^\]]+/

" Define stanzas
syn region confStanza matchgroup=confStanzaStart start=/^\[/ matchgroup=confStanzaEnd end=/\]/ oneline transparent contains=@confStanzas

" Group clusters
syn cluster confStanzas contains=confIndexesStanzas,confGenericStanzas

" indexes.conf
syn match   confIndexesStanzas contained /\v<(default|volume:[^\]]+)>/

syn match   confIndexes /\v<^(assureUTF8|bloomHomePath|bucketRebuildMemoryHint|cold(Path(\.maxDataSizeMB)?|ToFrozen(Dir|Script)))>/
syn match   confIndexes /\v<^(compressRawdata|createBloomfilter|datatype|defaultDatabase|deleted|disable(d|GlobalMetadata))>/
syn match   confIndexes /\v<^(enable(DataIntegrityControl|OnlineBucketRepair|RealtimeSearch|TsidxReduction)|lastChanceIndex)>/
syn match   confIndexes /\v<^(frozenTimePeriodInSecs|homePath(\.maxDataSizeMB)?|hotBucketTimeRefreshInterval|inPlaceUpdates)>/
syn match   confIndexes /\v<^((index|selfStorage)Threads|isReadOnly|journalCompression|max(BloomBackfillBucketAge|BucketSizeCacheEntries|ConcurrentOptimizes))>/
syn match   confIndexes /\v<^(max((DataSize|GlobalDataSizeMB)|Hot(Buckets|(Idle|Span)Secs)|MemMB|MetaEntries))>/
syn match   confIndexes /\v<^(max(RunningProcessGroups(LowPriority)?|TimeUnreplicated(NoAcks|WithAcks)|(Total|Volume)DataSizeMB|WarmDBCount))>/
syn match   confIndexes /\v<^(memPoolMB|min(HotIdleSecsBeforeForceRoll|RawFileSyncSecs|StreamGroupQueueSize)|partialServiceMetaPeriod|path)>/
syn match   confIndexes /\v<^(processTrackerServiceInterval|quarantine(Future|Past)Secs|queryLanguageDefinition|raw(Chunk|File)SizeBytes)>/
syn match   confIndexes /\v<^(recordreader\.(csv\.dialect|journal\.buffer\.size|name\.(conf_key|regex)))>/
syn match   confIndexes /\v<^(remote\.s3\.(access_key|auth_region|cipherSuite|dhFile|ecdhCurves|encryption(\.sse-c\.key_(refresh_interval|type))?))>/
syn match   confIndexes /\v<^(remote\.s3\.(endpoint|header\.[^\ |\=]+|kms\.(access_key|auth_region|key_id|max_concurrent_requests|secret_key|[^\ |\=]+)))>/
syn match   confIndexes /\v<^(remote\.s3\.(multipart_((down|up)load\.part_size|max_connections)|secret_key|signature_version))>/
syn match   confIndexes /\v<^(remote\.s3\.ssl((Alt|Common)NameToCheck|RootCAPath|VerifyServerCert|Versions))>/
syn match   confIndexes /\v<^(remote\.s3\.(supports_versioning|timeout\.(connect|read|write)|use_delimiter)|remotePath|repFactor)>/
syn match   confIndexes /\v<^(remote\.s3\.(enable_(data_integrity_checks|signed_payloads)|retry_policy|max_count\.max_retries_(per_part|in_total)))>/
syn match   confIndexes /\v<^(archiver\.selfStorage(Provider|Bucket(Folder)?))>/
syn match   confIndexes /\v<^(rotatePeriodInSecs|rtRouter(QueueSize|Threads)|service((InactiveIndexes|Meta|SubtaskTiming)Period|OnlyAsNeeded))>/
syn match   confIndexes /\v<^(split(ByIndexKeys|ter\.file\.split\.(max|min)size|ter\.name\.conf_key)|storageType|streamingTargetTsidxSyncPeriodMsec)>/
syn match   confIndexes /\v<^(summaryHomePath|suppressBannerList|suspendHotRollByDeleteQuery|sync(Meta)?|thawedPath|throttleCheckPeriod)>/
syn match   confIndexes /\v<^(timePeriodInSecBeforeTsidxReduction|tsidx(ReductionCheckPeriodInSec|StatsHomePath)|tstatsHomePath)>/
syn match   confIndexes /\v<^(vix\.(command(\.arg\.\d+)?|env\.(HUNK_THIRDPARTY_JARS|env)|family|fs\.default\.name))>/
syn match   confIndexes /\v<^(vix\.input\.\d+\.(accept|(e|l)t\.(format|offset|regex|timezone|value)|ignore|path|required\.fields))>/
syn match   confIndexes /\v<^(vix\.(javaprops\.JVM|kerberos\.(keytab|principal)|mapred\.job\.tracker|mode|property|provider))>/
syn match   confIndexes /\v<^(vix\.output\.buckets\.(from\.indexes|max\.network\.bandwidth|older\.than|path))>/
syn match   confIndexes /\v<^(vix\.splunk\.(heartbeat(\.interval|\.path|\.threshold)?|home\.(datanode|hdfs)|impersonation|jars))>/
syn match   confIndexes /\v<^(vix\.splunk\.search\.(column\.filter|debug|mixedmode(\.maxstream)?|mr\.mapper\.output\.(gzlevel|replication)))>/
syn match   confIndexes /\v<^(vix\.splunk\.search\.(mr\.((max|min)splits|poll|splits\.multiplier|threads)|recordreader(\.avro\.regex|\.sequence\.ignore\.key)?))>/
syn match   confIndexes /\v<^(vix\.splunk\.search\.splitter(\.hive\.(column(names|types)|dbname|fileformat(\.inputformat)?|ppd))?)>/
syn match   confIndexes /\v<^(vix\.splunk\.search\.splitter\.hive\.rowformat\.(collectionitems\.terminated|escaped|(fields|lines|mapkeys)\.terminated))>/
syn match   confIndexes /\v<^(vix\.splunk\.search\.splitter\.(hive\.(serde(\.properties)?|tablename)|parquet\.simplifyresult))>/
syn match   confIndexes /\v<^(vix\.splunk\.setup\.bundle\.(max\.inactive\.wait|poll\.interval|(reap|setup)\.timelimit|replication))>/
syn match   confIndexes /\v<^(vix\.splunk\.setup\.(onsearch|package(\.max\.inactive\.wait|\.poll\.interval|\.replication|\.setup\.timelimit)?))>/
syn match   confIndexes /\v<^(vix\.unified\.search\.cutoff_sec|warmToColdScript)>/

" 7.2.3
syn match   confIndexes /\v<^(bucketMerging|bucketMerge\.((min|max)MergeSizeMB|maxMergeTimeGapSecs)|hotlist_(recency_secs|bloom_filter_recency_hours))>/
syn match   confIndexes /\v<^(tsidxWritingLevel|archiver\.(coldStorage(Provider|RetentionPeriod)|enableDataArchive|maxDataArchiveRetentionPeriod))>/
syn match   confIndexes /\v<^(remote\.s3\.list_objects_version)>/

syn match   confIndexesConstants /\v<(auto(_high_volume)?|disable|excel(-tab)?|tsv|(text|sequence|rc)file|orc|gzip|lz4|zstd)$>/
syn match   confIndexesConstants /\v<(stream|report|infinite|default|sse-(s3|kms|c)|none|local|remote|event|metric|kms|v(1|2|4))$>/
syn match   confIndexesConstants /\v<(mtime|current|max_count)$>/

" 7.3.0
syn match   confIndexes /\v<^(malformedEventIndex|maxGlobalRawDataSizeMB)>/

" 8.1.0
syn match   confIndexes /\v<^(fileSystemExecutorWorkers|hotBucketStreaming.extraBucketBuildingCmdlineArgs|python\.version)>/
syn match   confIndexes /\v<^(metric\.(maxHotBuckets|splitByIndexKeys|enableFloatingPointCompression|compressionBlockSize|stubOutRawdataJournal|timestampResolution))>/
syn match   confIndexes /\v<^((metric\.)?tsidxTargetSizeMB|waitPeriodInSecsForManifestWrite)>/
syn match   confIndexes /\v<^(hotBucketStreaming\.(sendSlices|removeRemoteSlicesOnRoll|reportStatus|deleteHotsAfterRestart))>/
syn match   confIndexes /\v<^(remote\.s3\.(url_version|bucket_name|encryption\.cse\.(algorithm|tmp_dir|key_(type|refresh_interval))|max_download_batch_size))>/
syn match   confIndexes /\v<^(remote\.gs\.(credential_file|service_account_email|project_id|(upload|download)_chunk_size))>/
syn match   confIndexes /\v<^(remote\.gs\.(max_(parallel_non_upload_threads|threads_per_parallel_upload|connection_pool_size|download_batch_size|count\.max_retries_per_part)))>/
syn match   confIndexes /\v<^(remote\.gs\.(remove_all_versions|use_delimiter|retry_policy|backoff\.((initial|max)_delay_ms|scaling)))>/
syn match   confIndexes /\v<^(remote\.gs\.(connectUsingIpVersion|sslVerifyServer(Cert|Name)|sslVersionsForClient|sslRootCAPath))>/
syn match   confIndexes /\v<^(remote\.gs\.(cipherSuite|encryption(\.gcp-sse-c\.key_(type|refresh_interval))?))>/
syn match   confIndexes /\v<^(remote\.gs\.(gcp_kms\.(locations|key(_ring)?)))>/
syn match   confIndexes /\v<^(remote\.gs\.())>/
syn match   confIndexes /\v<^(remote\.gs\.())>/
syn match   confIndexes /\v<^(remote\.gs\.())>/
syn match   confIndexes /\v<^()>/
syn match   confIndexes /\v<^()>/
syn match   confIndexesConstants /\v<(default|python(2|3)?|aes-256-gcm|4-only|6-only|ssl3|tls1.(0|1|2)|gcp-sse-(c|kms|gcp))$>/

" 8.2
syn match   confIndexes /\v<^(bucketMerge\.maxMergeTimeSpanSecs|tsidxDedupPostingsListMaxTermsLimit|hotBucketStreaming\.removeRemoteSlicesOnFreeze)>/
syn match   confIndexes /\v<^(remote\.s3\.max_idle_connections|federated\.(provider|dataset))>/

" 9.0.0
syn match   confIndexes /\v<^(bucketMerge\.(min|max)MergeCount|deleteId|archiver\.selfStorage(DisableMPU|Encryption))>/
syn match   confIndexes /\v<^(remote\.s3\.(tsidx_compression|use_sdk))>/
syn match   confIndexes /\v<^(remote\.azure\.(sslVersions|sslVerifyServer(Cert|Name)|use_delimiter|httpKeepAlive|(access|secret)_key))>/
syn match   confIndexes /\v<^(remote\.azure\.((tenant|client)_id|client_secret|sslRootCAPath|cipherSuite|encryption|endpoint))>/
syn match   confIndexes /\v<^(remote\.azure\.(azure-sse-kv\.encryptionScope|supports_versioning|container_name|upload\.(chunk_size|concurrency)))>/
syn match   confIndexes /\v<^(remote\.azure\.(download\.(chunk_size|concurrency)|max_(download_batch|listing_page)_size|retry_policy))>/
syn match   confIndexes /\v<^(remote\.azure\.(max_count\.max_retries_in_total|backoff\.(initial|max_retry)_delay_ms))>/

syn match   confIndexesConstants /\v<(azure-sse-(kv|ms)|cse|(m)?s)$>/

" Highlight definitions (generic)
hi def link confComment Comment
hi def link confSpecComment Error
hi def link confBoolean Boolean
hi def link confTodo Todo

" Other highlight
hi def link confString String
hi def link confNumber Number
hi def link confPath   Number
hi def link confVar    PreProc

hi def link confStanzaStart Delimiter
hi def link confstanzaEnd Delimiter

" Highlight for stanzas
hi def link confStanza Function
hi def link confGenericStanzas Constant
hi def link confIndexesStanzas Identifier
hi def link confIndexes Keyword
hi def link confIndexesConstants Constant
