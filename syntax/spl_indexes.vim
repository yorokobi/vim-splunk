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
syn keyword confTodo FIXME[:] NOTE[:] TODO[:] contained

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
syn match   confIndexes /\v<^(indexThreads|isReadOnly|journalCompression|max(BloomBackfillBucketAge|BucketSizeCacheEntries|ConcurrentOptimizes))>/
syn match   confIndexes /\v<^(max((DataSize|GlobalDataSizeMB)|Hot(Buckets|(Idle|Span)Secs)|MemMB|MetaEntries))>/
syn match   confIndexes /\v<^(max(RunningProcessGroups(LowPriority)?|TimeUnreplicated(NoAcks|WithAcks)|(Total|Volume)DataSizeMB|WarmDBCount))>/
syn match   confIndexes /\v<^(memPoolMB|min(HotIdleSecsBeforeForceRoll|RawFileSyncSecs|StreamGroupQueueSize)|partialServiceMetaPeriod|path)>/
syn match   confIndexes /\v<^(processTrackerServiceInterval|quarantine(Future|Past)Secs|queryLanguageDefinition|raw(Chunk|File)SizeBytes)>/
syn match   confIndexes /\v<^(recordreader\.(csv\.dialect|journal\.buffer\.size|name\.(conf_key|regex)))>/
syn match   confIndexes /\v<^(remote\.s3\.(access_key|auth_region|cipherSuite|dhFile|ecdhCurves|encryption(\.sse-c\.key_(refresh_interval|type))?))>/
syn match   confIndexes /\v<^(remote\.s3\.(endpoint|header\.[^\ |\=]+|kms\.(access_key|auth_region|key_id|max_concurrent_requests|secret_key|[^\ |\=]+)))>/
syn match   confIndexes /\v<^(remote\.s3\.(multipart_(down|up)load\.part_size|secret_key|signature_version))>/
syn match   confIndexes /\v<^(remote\.s3\.ssl((Alt|Common)NameToCheck|RootCAPath|VerifyServerCert|Versions))>/
syn match   confIndexes /\v<^(remote\.s3\.(supports_versioning|timeout\.(connect|read|write)|use_delimiter)|remotePath|repFactor)>/
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

syn match   confIndexesConstants /\v<(auto(_high_volume)?|disable|excel(-tab)?|tsv|textfile|(sequence|rc)file|orc|gzip|lz4)$>/
syn match   confIndexesConstants /\v<(stream|report|infinite|default|sse-(s3|kms|c)|none|local|remote|event|metric|kms|v(2|4))$>/
syn match   confIndexesConstants /\v<(mtime|current)>/

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
