" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" inputs.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confInputsStanzas,confCommonStanzas,confCommonDeprecated,confGenericStanzas

" Stanzas
syn match   confInputsStanzas contained /\v<(blacklist:[^]]+|tcp(-ssl)?:(\/\/[^:]+:)?\d+|udp:(\/\/[^:]+:)?\d+|splunktcp((-ssl)?:(\/\/[^:]+:)?\d+)?)>/
syn match   confInputsStanzas contained /\v<(batch|monitor|fifo|script|perfmon|splunktcptoken|MonitorNoHandle|Win(EventLog|(Host|Net|Print|Reg)Mon)):\/\/[^\]]+>/
syn match   confInputsStanzas contained /\v<(admon|powershell(2)?):\/\/[^]]+>/
syn match   confInputsStanzas contained /\v<(SSL|fschange:[^]]+|filter:(white|black)list:[^]]+|http(:\/\/[^]]+)?)>/
syn match   confInputsStanzas contained /\v<(filter:[^:]+:[^\]]+|remote_queue:[^\]]+)>/
syn match   confInputsStanzas contained /\v<(powershell(2)?|journald:\/\/\k+|journald)>/
syn match   confInputsStanzas contained /\v<(logd:\/\/\k+|cloud_processor_smartbus_queue:\k+:\k+)>/

" Key words
syn match   confInputs /\v<^(host(_regex|_segment)?|index(es)?|source(type)?|queue|_(raw|meta|time|(TCP|SYSLOG|INDEX_AND_FORWARD)_ROUTING|rcvbuf))>/
syn match   confInputs /\v<^(crcSalt|initCrcLength|ignoreOlderThan|followTail|alwaysOpenFile|time_before_close|(white|black)list(\d+)?)>/
syn match   confInputs /\v<^(multiline_event_extra_waittime|recursive|followSymlink|move_policy|connection_host|(persistentQ|q)?ueueSize)>/
syn match   confInputs /\v<^(requireHeader|listenOnIPv6|acceptFrom|rawTcpDoneTimeout|route|enableS2SHeartbeat|(s2sHeartbeat|inputShutdown)Timeout)>/
syn match   confInputs /\v<^(stopAcceptorAfterQBlock|negotiateProtocolLevel|concurrentChannelLimit|compressed|token|stats)>/
syn match   confInputs /\v<^(serverCert|requireClientCert|cipherSuite|dhFile|allow(Ssl(Renegotiation|Compression)|QueryStringAuth))>/
syn match   confInputs /\v<^(ssl(Password|Versions|(Alt|Common)NameToCheck))>/
syn match   confInputs /\v<^(no_(priority_stripping|appending_timestamp)|interval|passAuth|send_index_as_argument_for_path|start(_by_shell|_from|ingNode))>/
syn match   confInputs /\v<^(signedaudit|filters|recurse|followLinks|pollPeriod|(hash|sendEvent)MaxSize|fullEvent|filesPerDelay|delayInMills)>/
syn match   confInputs /\v<^(regex\d+|port|disabled|outputgroup|use(ACK|DeploymentServer|EnglishOnly|_old_eventlog_api|_threads|r(BufferSize)?))>/
syn match   confInputs /\v<^(enableSSL|dedicatedIoThreads|replyHeader\.\w+|max(Sockets|Threads|IdleTime))>/
syn match   confInputs /\v<^((busyK|k)eepAliveIdleTimeout|crossOriginSharingPolicy|forceHttp10|sendStrictTransportSecurityHeader)>/
syn match   confInputs /\v<^(ackIdleCleanup|channel_cookie|description|addressFamily|baseline(_interval)?|batch_size|(checkpoint|read|sampling)Interval)>/
syn match   confInputs /\v<^(counters|current_only|direction|driverBufferSize|formatString|hive|instances|mode|monitorSubtree|object|packetType)>/
syn match   confInputs /\v<^(evt_((ad|sid)_cache_(disabled|exp(_neg)?|max_entries)|(dc|dns)_name|resolve_ad_(ds|obj))|multikvMax(EventCount|TimeMs))>/
syn match   confInputs /\v<^(printSchema|pro(c(ess)?|tocol)|remoteAddress|renderXml|schedule|script|showZeroValue|sid_cache_(disabled|exp(_neg)?|max_entries))>/
syn match   confInputs /\v<^(suppress_(checkpoint|keywords|opcode|sourcename|task|text|type)|targetDc|thread_wait_time_msec|type)>/
syn match   confInputs /\v<^(remote_queue\.sqs\.((access|secret)_key|auth_region|endpoint|max_connections))>/
syn match   confInputs /\v<^(remote_queue\.sqs\.(message_group_id|retry_policy|max_count\.max_retries_per_part))>/
syn match   confInputs /\v<^(remote_queue\.sqs\.(timeout\.(connect|read|write|receive_message|visibility)))>/
syn match   confInputs /\v<^(remote_queue\.sqs\.(buffer\.visibility|min_pending_messages|large_message_store\.(endpoint|path)))>/
syn match   confInputs /\v<^(channel(TTL|Reap(Interval|Lowater))|maxEventSize|remote_queue\.type)>/
syn match   confInputs /\v<^(remote_queue\.kinesis\.((access|secret)_key|auth_region|endpoint|retry_policy))>/
syn match   confInputs /\v<^(remote_queue\.kinesis\.(max_count\.max_retries_per_part|timeout\.(connect|read|write)))>/
syn match   confInputs /\v<^(remote_queue\.kinesis\.(max_(messages|checkpoints)|min_pending_messages|roll_remote_buckets_interval))>/
syn match   confInputs /\v<^(remote_queue\.kinesis\.large_message_store\.(endpoint|path))>/
syn match   confInputs /\v<^(log_on_completion|useSSLCompression|use(WinApiProcStats|PDHFmtNoCap100)|run_introspection)>/
syn match   confInputs /\v<^(remote_queue\.((sqs|kinesis)\.executor_max_workers_count|large_message_store\.supports_versioning))>/
syn match   confInputs /\v<^(crossOriginSharingHeaders|evt_exclude_fields|(io|serialization)_threads|event_serialization_format)>/
syn match   confInputs /\v<^(remote_queue.sqs_smartbus.((access|secret)_key|auth_region|endpoint|max_connections|message_group_id|retry_policy))>/
syn match   confInputs /\v<^(remote_queue.sqs_smartbus.(max_count.max_retries_per_part|timeout.(connect|read|write|receive_message|visibility)))>/
syn match   confInputs /\v<^(remote_queue.sqs_smartbus.(buffer.visibility|executor_max_workers_count|min_pending_messages|large_message_store.(endpoint|path)))>/
syn match   confInputs /\v<^(remote_queue.sqs_smartbus.(dead_letter_queue.(name|process_interval))|run_only_one)>/
syn match   confInputs /\v<^(remote_queue.sqs_smartbus.large_message_store.(encryption_scheme|kms_endpoint|key_(id|refresh_interval)))>/
syn match   confInputs /\v<^(logCertificateData|certLog(MaxCacheEntries|RepeatFrequency)|sslServerHandshakeTimeout|nonmetric_counters)>/
syn match   confInputs /\v<^()>/
syn match   confInputs /\v<^(remote_queue.sqs.smartbus.(renew_retries)|evt_skip_GUID_resolution|logRetireOldS2S(MaxCache|RepeatFrequency)?)>/
syn match   confInputs /\v<^(remote_queue.sqs.smartbus.(large_message_store\.(ssl(VerifyServerCert|Versions|(Alt|Common)NameToCheck|RootCAPath)|cipherSuite|ecdhCurves|dhFile)))>/
syn match   confInputs /\v<^(rollingRestartReturnServerBusy|wec_event_format|checkpointSync|channel_wait_time)>/
syn match   confInputs /\v<^(logd-(backtrace|debug|info|loss|signpost|predicate|process|source|(in|ex)clude-fields|interval|starttime|freetext))>/
syn match   confInputs /\v<^(s2s_indexes_validation|process_completion_check_interval|remote_queue\.\k+|encoding_format)>/
syn match   confInputs /\v<^(retry_policy|max_count\.max_retries_per_part)>/
syn match   confInputs /\v<^(large_message_store\.(sslVerifyServerCert|sslVersions|sslRootCAPath|cipherSuite|ecdhCurves|encryption_scheme|key_refresh_interval))>/
syn match   confInputs /\v<^(backpressureState|remote\.asq\.backoff\.(initial|max_retry)_delay)>/
syn match   confInputs /\v<^(jsonParser(MaxEventSize)?|ackExpiryMode|headerEnforcementMode|ackRequiredAnyCookie)>/
syn match   confInputs /\v<^(maxMemoryUsagePct|hecCacheCapacity|customMetadataMode|asq)>/
syn match   confInputs /\v<^(remote_queue.gcs_smartbus.(pubsub|storage)_endpoint|adsUseSSL)>/
syn match   confInputs /\v<^(journalctl-(in|ex)clude-fields|journalctl-(filter|(user-)?unit|identifier|priority|boot|facility|grep))>/
syn match   confInputs /\v<^(journalctl-(dmesg|quiet|freetext))>/

" Constants
syn match   confInputsConstants /\v<((parsing|index)Queue|auto|never|always|yes|no|only|(proxied_)?ip|dns|none|PDC|single|multikv|sinkhole)$>/
syn match   confInputsConstants /\v<(connect|accept|transport|tcp|udp|has_key|absent_key:[^:]+:[^\ |\=]+|ipv(4|6)|(in|out)bound)$>/
syn match   confInputsConstants /\v<(average|(max_)?count|dev|min|max|sqs|kinesis|kv|json|sqs_smartbus|sse-(s3|c))$>/
syn match   confInputsConstants /\v<(disabled_for_internal|enabled_for_all|sqs_(datalake|smartbus_cp))$>/
syn match   confInputsConstants /\v<(warn(_at_80)?|legacy|vectorized|expire_at_90|block|query_string|(raw|rendered)_event)$>/
syn match   confInputsConstants /\v<(gcp-sse-(c|kms|gcp)|gcp_kms)$>/
syn match   confInputsConstants /\v<(__(MONOTONIC|(SOURCE_)?REALTIME)_TIMESTAMP|MESSAGE|PRIORITY|_SYSTEMD_(UNIT|CGROUP)|_TRANSPORT|_(P|U|G)ID)>/
syn match   confInputsConstants /\v<(_MACHINE_ID|_COMM|_EXE|__CURSOR)>/

" Deprecated
syn match   confInputsDeprecated /\v<^((_)(white|black)list(\d+)?|negotiateNewProtocol|password|rootCA|supportSSLV3Only|ecdhCurveName)>/
syn match   confInputsDeprecated /\v<^(dhfile|sslQuietShutdown|sslKeysfile(Password)?|ca(CertFile|Path))>/

hi def link confInputsStanzas Identifier
hi def link confInputs Keyword
hi def link confInputsConstants Constant
hi def link confInputsDeprecatedStanzas Removed
hi def link confInputsDeprecated Removed
