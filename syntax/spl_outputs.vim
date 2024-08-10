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
syn cluster confStanzas contains=confOutputsStanzas,confGenericStanzas

" outputs.conf
syn match   confOutputsStanzas contained /\v<(default|indexAndForward|indexer_discovery:[^]]+|syslog(:[^]]+)?|tcpout(-server:\/\/\S+:\d+|:[^]]+)?|remote_queue:\S+)>/

syn match   confOutputs /\v<^(ackTimeoutOnShutdown|autoLB(Frequency|Volume)|backoffOnFailure|block(OnCloning|WarnThreshold)|channel(Reap(Interval|Lowater)|TTL))>/
syn match   confOutputs /\v<^(cipherSuite|clientCert|compressed|(connection|read|write)Timeout|(cxn|rcv|send)_timeout|defaultGroup|(dnsResolution|secsInFailure)Interval|drop(Cloned)?EventsOnQueueFull)>/
syn match   confOutputs /\v<^(ecdhCurves|forceTimebasedAutoLB|forwardedindex\.(\d+\.(black|white)list|filter\.disable)|heartbeatFrequency|index(AndForward|erDiscovery)?)>/
syn match   confOutputs /\v<^((manager|master)_uri|max(ConnectionsPerIndexer|(Event|Queue)Size|FailuresPerInterval)|negotiate(NewProtocol|ProtocolLevel)|pass4SymmKey)>/
syn match   confOutputs /\v<^(priority|selectiveIndexing|sendCookedData|server|socks(Password|ResolveDNS|Server|Username)|syslogSourceType|tcpSendBufSz)>/
syn match   confOutputs /\v<^(ssl((Alt|Common)NameToCheck|(Cert|RootCA)Path|Cipher|Password|QuietShutdown|VerifyServerCert|Versions))>/
syn match   confOutputs /\v<^(timestampformat|tlsHostname|token|type|use(ACK|ClientSSLCompression))>/

" ----------
"  7.1
" ----------
syn match   confOutputs /\v<^(remote_queue\.|remote_queue\.sqs\.((access|secret)_key|auth_region|endpoint|message_group_id|retry_policy|max_count\.max_retries_per_part|timeout\.(connect|read|write)))>/
syn match   confOutputs /\v<^(remote_queue\.sqs\.(large_message_store\.(endpoint|path)|send_interval|max_queue_message_size|enable_(data_integrity_checks|signed_payloads)))>/
syn match   confOutputs /\v<^(concurrentChannelLimit)>/

syn match   confOutputsConstants /\v<(auto|NO_PRI|tcp|udp|max_count|none)$>/

" 7.2.3
syn match   confOutputs /\v<^(useSSL|remote_queue\.type|remote_queue\.kinesis\.((access|secret)_key|auth_region|endpoint))>/
syn match   confOutputs /\v<^(remote_queue\.kinesis\.(enable_(data_integrity_checks|signed_payloads)|retry_policy))>/
syn match   confOutputs /\v<^(remote_queue\.kinesis\.(max_count.max_retries_per_part|timeout\.(connect|read|write)))>/
syn match   confOutputs /\v<^(remote_queue\.kinesis\.large_message_store\.(endpoint|path))>/
syn match   confOutputs /\v<^(remote_queue\.kinesis\.(send_interval|max_queue_message_size))>/
syn match   confOutputsConstants /\v<(legacy|sqs|kinesis)$>/

" 8.0.0
syn match   confOutputs /\v<^(connectionTTL|remote_queue\.kinesis\.tenantId)>/

" 8.1.0
syn match   confOutputsStanzas contained /\v<(httpout)>/

syn match   confOutputs /\v<^(httpEventCollectorToken|uri|batch(Size|Timeout))>/
syn match   confOutputs /\v<^(remote_queue\.sqs_smartbus\.((access|secret)_key|auth_region|endpoint|message_group_id|retry_policy))>/
syn match   confOutputs /\v<^(remote_queue\.sqs_smartbus\.(max_count\.max_retries_per_part|timeout\.(connect|read|write)))>/
syn match   confOutputs /\v<^(remote_queue\.sqs_smartbus\.(large_message_store\.(endpoint|path)|send_interval|max_queue_message_size))>/
syn match   confOutputs /\v<^(remote_queue\.sqs_smartbus\.(enable_(data_integrity_checks|signed_payloads)|executor_max_(workers|jobs)_count))>/

syn match   confOutputsConstants /\v<(sqs(_smartbus(_cp)?)|kinesis)$>/

" 8.2
syn match   confOutputs /\v<^(polling_interval|maxSendQSize|remote_queue.sqs_smartbus.encoding_format)>/
syn match   confOutputs /\v<^(remote_queue.sqs_smartbus.large_message_store.(encryption_scheme|kms_endpoint|key_(id|refresh_interval)))>/

syn match   confOutputsConstants /\v<(protobuf|s2s|sse-(s3|c))$>/

" 9.0.0
syn match   confOutputsStanzas contained /\v<(rfs(:\k+)?)>/

syn match   confOutputs /\v<^(connectionsPerTarget|autoLBFrequencyIntervalOnGroupFailure|autoBatch|sslVerifyServerName)>/
syn match   confOutputs /\v<^(remote_queue.sqs_smartbus.large_message_store.(ssl(VerifyServerCert|Versions|(Alt|Common)NameToCheck|RootCAPath)))>/
syn match   confOutputs /\v<^(remote_queue.sqs_smartbus.large_message_store.(cipherSuite|ecdhCurves|dhFile))>/
syn match   confOutputs /\v<^(dropEventsOnUploadError|batchSizeThresholdKB|compression(Level)?|path|description)>/
syn match   confOutputs /\v<^(remote.s3.(encryption|(access|secret)_key|(signature|url)_version|supports_versioning|endpoint|retry_policy))>/
syn match   confOutputs /\v<^(remote.s3.(ssl(VerifyServerCert|Versions|(Alt|Common)NameToCheck|RootCAPath)|cipherSuite|ecdhCurves))>/
syn match   confOutputs /\v<^(remote.s3.(kms.(auth_region|key_id)|authMethod))>/
syn match   confOutputs /\v<^(partitionBy|metadata_max_attempts)>/
syn match   confOutputs /\v<^(remote\.s3\.kms\.(ssl(VerifyServerCert|Versions|RootCAPath|AltNamesToCheck|CommonNameToCheck)|cipherSuite|ecdhCurves|dhFile))>/

syn match   confOutputsConstants /\v<(sse-(s3|kms)|cse|zstd|lz4|gzip)$>/
syn match   confOutputsConstants /\v<(legacy|year|month|day|sourcetype)$>/

" 9.1.0
syn match   confOutputs /\v<^(enableOldS2SProtocol|partitionBy|format(\.(nd)?json\.index_time_fields)?|disabled|)>/
syn match   confOutputs /\v<^(remote_queue\.sqs_smartbus\.(consume_interval|drop_data(_index_list)?|enable_inline_data))>/
syn match   confOutputs /\v<^(remote\.s3\.auth_region)>/

syn match   confOutputsConstants /\v<((nd)?json|raw)$>/

" 9.3.0
syn match   confOutputsStanzas contained /\v<(cloud_processing_queue)>/
syn match   confOutputs /\v<^(certRotationCheckInterval|autoCertRotation)>/
syn match   confOutputs /\v<^(remote_queue\.sqs_smartbus\.check_replication_(enabled|interval|executor_max_workers_count|executor_max_jobs_count))>/
syn match   confOutputs /\v<^(remote_queue\.sqs_smartbus\.enable_shared_receipts|fs\.appendToFileUntilSizeMB|fs\.timeBeforeClosingFileSecs)>/
syn match   confOutputs /\v<^(remote\.s3\.metadata_max_attempts|remote\.sts\.assume_role\.(role_arn|external_id|duration_secs)|authMethod)>/


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
hi def link confOutputsStanzas Identifier
hi def link confOutputs Keyword
hi def link confOutputsConstants Constant
