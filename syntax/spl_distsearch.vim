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
syn match  confPath   ,\v(^|\s|\=)\zs(file:|https?:|\$\k+)?(/+\k+)+(:\d+)?,
syn match  confPath   ,\v(^|\s|\=)\zsvolume:\k+(/+\k+)+,
syn match  confVar    /\$\k\+\$/

syn keyword confBoolean on off t[rue] f[alse] T[rue] F[alse]
syn keyword confTodo FIXME[:] NOTE[:] TODO[:] CAUTION[:] contained

" Define generic stanzas
syn match confGenericStanzas display contained /\v[^\]]+/

" Define stanzas
syn region confStanza matchgroup=confStanzaStart start=/^\[/ matchgroup=confStanzaEnd end=/\]/ oneline transparent contains=@confStanzas

" Group clusters
syn cluster confStanzas contains=confDistSearchStanzas,confGenericStanzas

" distsearch.conf
syn match   confDistSearchStanzas contained /\v<(default|distributedSearch(:[^]]+)?|tokenExchKeys|replication(Settings(:refineConf)?|(White|Black)list))>/
syn match   confDistSearchStanzas contained /\v<(bundleEnforcer(Black|White)list|searchhead:[^]]+)>/
syn match   confDistSearch /\v<^(disabled|heartbeat(McastAddr|Port|Frequency)|ttl|statusTimeout|removedTimedOutServers|checkTimedOutServersFrequency)>/
syn match   confDistSearch /\v<^(autoAddServers|bestEffortSearch|skipOurselves|(disabled_|quarantined_)?servers|shareBundles|useSHPBundleReplication)>/
syn match   confDistSearch /\v<^(trySSLFirst|(peerResolution|replication)Threads|defaultUriScheme)>/
syn match   confDistSearch /\v<^((sendRcv|server|connection|send|receive|(authToken(Connection|Send|Receive)))Timeout)>/
syn match   confDistSearch /\v<^(certDir|(public|private)Key|genKeyScript|allow(SkipEncoding|(Stream|Delta)Upload)|sanitizeMetaFiles)>/
syn match   confDistSearch /\v<^((max(Memory)?Bundle|concerningReplicatedFile|excludeReplicatedLookup)Size)>/
syn match   confDistSearch /\v<^(replicate\.[^\ |\=]+|mounted_bundles|bundles_location|default)>/

" 7.2.3
syn match   confDistSearch /\v<^(useDisabledListAsBlacklist|enableRFSMonitoring|rfsMonitoringPeriod|rfsSyncReplicationTimeout)>/
syn match   confDistSearch /\v<^(path|remote\.s3\.(endpoint|encryption))>/

syn match   confDistSearchConstants /\v<(auto|always|http(s)?|sse-s3|none)$>/

" 7.3.0
syn match   confDistSearch /\v<^(bcs(Path)?|enableRFSReplication)>/

" 8.0.0
syn match   confDistSearch /\v<^(replicationPolicy|statusQueueSize|cascade_replication_status_(interval|unchanged_threshold)|activeServerTimeout|remote\.s3\.(url_version|bucket_name|supports_versioning))>/
syn match   confDistSearchConstants /\v<(classic|cascading|rfs|mounted|v(1|2))$>/

" 8.1.0
syn match   confDistSearch /\v<^(minKeyLength|legacyKeyLengthAuthPolicy|warnMaxBundleSizePerc|allowDeltaIndexing)>/
syn match   confDistSearchConstants /\v<(reject|warn)$>/

" 8.2
syn match   confDistSearch /\v<^(preCompressKnowledgeBundles(Classic|Cascade)Mode)>/

" 9.0.0
syn match   confDistSearchStanzas contained /\v<(replication(Allow|Deny)list|bundleEnforcer(Allow|Deny)list)>/
syn match   confDistSearch /\v<^(cascade_plan_replication_(retry_fast|threshold_failures))>/

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
hi def link confDistSearchStanzas Identifier
hi def link confDistSearch Keyword
hi def link confDistSearchConstants Constant
