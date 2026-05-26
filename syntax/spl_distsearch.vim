" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" distsearch.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confDistSearchStanzas,confDistSearchDeprecatedStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confDistSearchStanzas contained /\v<(distributedSearch(:[^]]+)?|tokenExchKeys|replication(Settings(:refineConf)?))>/
syn match   confDistSearchStanzas contained /\v<(replication(Allow|Deny)list|bundleEnforcer(Allow|Deny)list)>/
syn match   confDistSearchStanzas contained /\v<(replicationSettings:fileSpecific|searchhead:[^]]+)>/

" Key words
syn match   confDistSearch /\v<^(statusTimeout|removedTimedOutServers|checkTimedOutServersFrequency)>/
syn match   confDistSearch /\v<^(bestEffortSearch|(disabled_|quarantined_)?servers|shareBundles|useSHPBundleReplication)>/
syn match   confDistSearch /\v<^(trySSLFirst|(peerResolution|replication)Threads|defaultUriScheme)>/
syn match   confDistSearch /\v<^((sendRcv|server|connection|send|receive|(authToken(Connection|Send|Receive)))Timeout)>/
syn match   confDistSearch /\v<^(certDir|(public|private)Key|genKeyScript|allowDelta(Upload|Indexing)|sanitizeMetaFiles)>/
syn match   confDistSearch /\v<^((max(Memory)?Bundle|concerningReplicatedFile|excludeReplicatedLookup)Size)>/
syn match   confDistSearch /\v<^(replicate\.[^\ |\=]+|mounted_bundles|bundles_location|default)>/
syn match   confDistSearch /\v<^(useDisabledListAsBlacklist|enableRFSMonitoring|rfsMonitoringPeriod|rfsSyncReplicationTimeout)>/
syn match   confDistSearch /\v<^(path|remote\.s3\.(endpoint|encryption)|bcs(Path)?|enableRFSReplication)>/
syn match   confDistSearch /\v<^(replicationPolicy|statusQueueSize|cascade_replication_status_(interval|unchanged_threshold))>/
syn match   confDistSearch /\v<^(|activeServerTimeout|remote\.s3\.(url_version|bucket_name|supports_versioning))>/
syn match   confDistSearch /\v<^(minKeyLength|legacyKeyLengthAuthPolicy|warnMaxBundleSizePerc)>/
syn match   confDistSearch /\v<^(preCompressKnowledgeBundles(Classic|Cascade)Mode)>/
syn match   confDistSearch /\v<^(cascade_plan_replication_(retry_fast|threshold_failures))>/
syn match   confDistSearch /\v<^(parallelReduceBackwardCompatibility|searchableIndexMapping)>/
syn match   confDistSearch /\v<^(useIPAddrAsHost|bundleTransferTimeout|slowReplicationLoggingInterval)>/
syn match   confDistSearch /\v<^(useChecksumforDeltaCalculation|rfsMaxDeltaCountBetweenFull)>/

" Constants
syn match   confDistSearchConstants /\v<(auto|always|http(s)?|sse-s3|none)$>/
syn match   confDistSearchConstants /\v<(classic|cascading|rfs|mounted|v(1|2))$>/
syn match   confDistSearchConstants /\v<(reject|warn|allow|deny)$>/
syn match   confDistSearchConstants /\v<(cloud|enterprise|(en|dis)abled)$>/

" Deprecated Stanzas
syn match   confDistSearchDeprecatedStanzas contained /\v<(replication(White|Black)list|bundleEnforcer(White|Black)list)>/

" Deprecated key words
syn match   confDistSearchDeprecated /\v<^(heartbeat(McastAddr|Port|Frequency)|autoAddServers|skipOurselves|ttl)>/
syn match   confDistSearchDeprecated /\v<^(allowStreamUpload|allowSkipEncoding|maxMemoryBundleSize)>/

" Highlighting
hi def link confDistSearchStanzas Identifier
hi def link confDistSearch Keyword
hi def link confDistSearchConstants Constant
hi def link confDistSearchDeprecatedStanzas Removed
hi def link confDistSearchDeprecated Removed
