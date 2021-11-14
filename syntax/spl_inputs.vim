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
syn cluster confStanzas contains=confInputsStanzas,confGenericStanzas

" inputs.conf
syn match   confInputsStanzas contained /\v<(default|blacklist:[^]]+|tcp(-ssl)?:(\/\/[^:]+:)?\d+|udp:(\/\/[^:]+:)?\d+|splunktcp((-ssl)?:(\/\/[^:]+:)?\d+)?)>/
syn match   confInputsStanzas contained /\v<(batch|monitor|fifo|script|perfmon|splunktcptoken|MonitorNoHandle|Win(EventLog|(Host|Net|Print|Reg)Mon)):\/\/[^]]+>/
syn match   confInputsStanzas contained /\v<(admon|powershell(2)?):\/\/[^]]+>/
syn match   confInputsStanzas contained /\v<(SSL|fschange:[^]]+|filter:(white|black)list:[^]]+|http(:\/\/[^]]+)?)>/

" ------------------------
"  Splunk 6.6
" ------------------------
syn match   confInputsStanzas contained /\v<(filter:[^:]+:[^\]]+)>/

" -----------------------
"  Splunk 7.1
" -----------------------
syn match   confInputsStanzas contained /\v<(remote_queue:[^\]]+)>/

syn match   confInputs /\v<^(host(_regex|_segment)?|index(es)?|source(type)?|queue|_(raw|meta|time|(TCP|SYSLOG|INDEX_AND_FORWARD)_ROUTING|rcvbuf))>/
syn match   confInputs /\v<^((_)?(white|black)list(\d+)?|crcSalt|initCrcLength|ignoreOlderThan|followTail|alwaysOpenFile|time_before_close)>/
syn match   confInputs /\v<^(multiline_event_extra_waittime|recursive|followSymlink|move_policy|connection_host|(persistentQ|q)?ueueSize)>/
syn match   confInputs /\v<^(requireHeader|listenOnIPv6|acceptFrom|rawTcpDoneTimeout|route|enableS2SHeartbeat|(s2sHeartbeat|inputShutdown)Timeout)>/
syn match   confInputs /\v<^(stopAcceptorAfterQBlock|negotiate(ProtocolLevel|NewProtocol)|concurrentChannelLimit|compressed|token|stats)>/
syn match   confInputs /\v<^(serverCert|requireClientCert|cipherSuite|ecdhCurve(s|Name)|dh(F|f)ile|allow(Ssl(Renegotiation|Compression)|QueryStringAuth))>/
syn match   confInputs /\v<^(ssl(Password|Versions|QuietShutdown|(Alt|Common)NameToCheck|Keysfile(Password)?)|password|rootCA|supportSSLV3Only)>/
syn match   confInputs /\v<^(no_(priority_stripping|appending_timestamp)|interval|passAuth|send_index_as_argument_for_path|start(_by_shell|_from|ingNode))>/
syn match   confInputs /\v<^(signedaudit|filters|recurse|followLinks|pollPeriod|(hash|sendEvent)MaxSize|fullEvent|filesPerDelay|delayInMills)>/
syn match   confInputs /\v<^(regex\d+|port|disabled|outputgroup|use(ACK|DeploymentServer|EnglishOnly|_old_eventlog_api|_threads|r(BufferSize)?))>/
syn match   confInputs /\v<^(enableSSL|dedicatedIoThreads|replyHeader\.\w+|max(Sockets|Threads|IdleTime))>/
syn match   confInputs /\v<^((busyK|k)eepAliveIdleTimeout|ca(CertFile|Path)|crossOriginSharingPolicy|forceHttp10|sendStrictTransportSecurityHeader)>/
syn match   confInputs /\v<^(ackIdleCleanup|channel_cookie|description|addressFamily|baseline(_interval)?|batch_size|(checkpoint|read|sampling)Interval)>/
syn match   confInputs /\v<^(counters|current_only|direction|driverBufferSize|formatString|hive|instances|mode|monitorSubtree|object|packetType)>/
syn match   confInputs /\v<^(evt_((ad|sid)_cache_(disabled|exp(_neg)?|max_entries)|(dc|dns)_name|resolve_ad_(ds|obj))|multikvMax(EventCount|TimeMs))>/
syn match   confInputs /\v<^(printSchema|pro(c(ess)?|tocol)|remoteAddress|renderXml|schedule|script|showZeroValue|sid_cache_(disabled|exp(_neg)?|max_entries))>/
syn match   confInputs /\v<^(suppress_(checkpoint|keywords|opcode|sourcename|task|text|type)|targetDc|thread_wait_time_msec|type)>/

" -----------------------
"  Splunk 7.1
" -----------------------
syn match   confInputs /\v<^(remote_queue\.sqs\.((access|secret)_key|auth_region|endpoint|max_connections))>/
syn match   confInputs /\v<^(remote_queue\.sqs\.(message_group_id|retry_policy|max_count\.max_retries_per_part))>/
syn match   confInputs /\v<^(remote_queue\.sqs\.(timeout\.(connect|read|write|receive_message|visibility)))>/
syn match   confInputs /\v<^(remote_queue\.sqs\.(buffer\.visibility|min_pending_messages|large_message_store\.(endpoint|path)))>/
syn match   confInputs /\v<^(channel(TTL|Reap(Interval|Lowater)))>/

" 7.2.3
syn match   confInputs /\v<^(maxEventSize|remote_queue\.type)>/
syn match   confInputs /\v<^(remote_queue\.kinesis\.((access|secret)_key|auth_region|endpoint|retry_policy))>/
syn match   confInputs /\v<^(remote_queue\.kinesis\.(max_count\.max_retries_per_part|timeout\.(connect|read|write)))>/
syn match   confInputs /\v<^(remote_queue\.kinesis\.(max_(messages|checkpoints)|min_pending_messages|roll_remote_buckets_interval))>/
syn match   confInputs /\v<^(remote_queue\.kinesis\.large_message_store\.(endpoint|path))>/

syn match   confInputsConstants /\v<((parsing|index)Queue|auto|never|always|yes|no|only|(proxied_)?ip|dns|none|PDC|single|multikv|sinkhole)$>/
syn match   confInputsconstants /\v<(connect|accept|transport|tcp|udp|has_key|absent_key:[^:]+:[^\ |\=]+|ipv(4|6)|(in|out)bound)$>/
syn match   confInputsConstants /\v<(average|(max_)?count|dev|min|max|sqs|kinesis)$>/

" 7.3.0
syn match   confInputs /\v<^(log_on_completion|useSSLCompression|use(WinApiProcStats|PDHFmtNoCap100)|run_introspection)>/
syn match   confInputs /\v<^(remote_queue\.((sqs|kinesis)\.executor_max_workers_count|large_message_store\.supports_versioning))>/

" 8.1.0
syn match   confInputsStanzas contained /\v<(powershell(2)?|journald:\/\/[^\]]+|journald)>/

syn match   confInputs /\v<^(python\.version|crossOriginSharingHeaders|evt_exclude_fields|(io|serialization)_threads|event_serialization_format)>/
syn match   confInputs /\v<^(remote_queue.sqs_smartbus.((access|secret)_key|auth_region|endpoint|max_connections|message_group_id|retry_policy))>/
syn match   confInputs /\v<^(remote_queue.sqs_smartbus.(max_count.max_retries_per_part|timeout.(connect|read|write|receive_message|visibility)))>/
syn match   confInputs /\v<^(remote_queue.sqs_smartbus.(buffer.visibility|executor_max_workers_count|min_pending_messages|large_message_store.(endpoint|path)))>/
syn match   confInputs /\v<^(remote_queue.sqs_smartbus.(dead_letter_queue.(name|process_interval)))>/

syn match   confInputsConstants /\v<(default|python(2|3)?|kv|json|sqs_smartbus)$>/

" 8.2
syn match   confInputs /\v<^(remote_queue.sqs_smartbus.large_message_store.(encryption_scheme|kms_endpoint|key_(id|refresh_interval)))>/
syn match   confInputs /\v<^(run_only_one)>/

syn match   confInputsConstants /\v<(sse-(s3|c))>/

" UF journalctl
syn match   confInputs /\v<^(journalctl-(in|ex)clude-fields|journalctl-(filter|(user-)?unit|identifier|priority|boot|facility|grep))>/
syn match   confInputs /\v<^(journalctl-(dmesg|quiet|freetext))>/

syn match   confInputsConstants /\v<(__(MONOTONIC|(SOURCE_)?REALTIME)_TIMESTAMP|MESSAGE|PRIORITY|_SYSTEMD_(UNIT|CGROUP)|_TRANSPORT|_(P|U|G)ID)>/
syn match   confInputsConstants /\v<(_MACHINE_ID|_COMM|_EXE|__CURSOR)>/

" Splunk_TA_okta
syn match   confInputs /\v<^(url|token|(start|end)_date|metrics|(page|batch)_size)>/

" Splunk_TA_jmx
syn match   confInputs /\v<^(config_file(_dir)?|polling_frequency)>/
syn match   confInputsConstants /\v<((parsing|index)Queue)$>/

" TA_Azure
syn match   confInputs /\v<^(storage_account|access_key|limit|pollingInterval|site_diagnostics_container|subscription_id|api_version|token_endpoint|table_name|select_str ing)>/
syn match   confInputs /\v<^(enableWAD(MetricsPT1(H|M)|(PerformanceCounters|DiagnosticInfrastructureLogs|WindowsEventLogs)Table)|client_(id|secret)|dateTime(Column|Start))>/

" ITSI
syn match   confInputs /\v<^((default|required_ui)_severity|suppress|debug|acceleration|manual_rebuilds|always_exec|group|execution_order|timeout)>/
syn match   confInputs /\v<^(app_name|log_level|registered_capabilities|import_from_search|csv_location|search_string|selected_services|update_type|owner)>/
syn match   confInputs /\v<^(app(s_to_update|(_exclude)?_regex|_include_list)|endpoint(_params)?|index_(earliest|latest))>/
syn match   confInputs /\v<^(service_(rel|title_field|description_column))>/
syn match   confInputs /\v<^(entity_(title_field|service_columns|identifier_fields|description_column|informational_fields|field_mapping))>/
syn match   confInputsConstants /\v<(DEBUG|INFO|WARN|ERROR|CRITICAL|FATAL)$>/

" Splunk_TA_f5-bigip
syn match   confInputs /\v<^(nothing)>/

" Splunk_TA_ibm-was
syn match   confInputs /\v<^(was_data_input)>/

" Splunk DB Connect 3.1.1
syn match   confInputsStanzas contained /\v<(server:\/\/[^]]+)>/
syn match   confInputs /\v<^(config_file|keystore_password|interval)>/
"syn match   confInputsStanzas contained /\v<(mi_output)>/
"syn match   confInputs /\v<^(policy|connection|key_pattern|javahome|options|port|bindIP|proc_pid|useSSL|keystore_password|Exception|cert_(file|validity))>/
"syn match   confInputs /\v<^(output_timestamp_format|resource_pool|auto_disable|max_retries|syn|match|confInputs|user|description|mode|connection|query(_timeout))>/
"syn match   confInputs /\v<^(max_rows|(is_saved_)?search|time_out|transactional|customized_mappings|max_single_checkpoint_file_size)>/
"syn match   confInputs /\v<^((lookup|update|reload)SQL|(input|output)_fields)>/
"syn match   confInputs /\v<^(ui_(query_(mode|catalog|schema|table)|input_((spl|saved)_search)|use_saved_search|is_auto_lookup|query_result_columns|column_output_map|field _column_map|auto_lookup_conditions|mappings|selected_fields|saved_search_str|query_sql))>/
"syn match   confInputs /\v<^(tail_(follow_only|rising_column_((full)?name|number|checkpoint_value)))>/
"syn match   confInputs /\v<^(input_timestamp_(format|column_((full)?name|number)))>/
"syn match   confInputsConstants /\v<(reload|update|simple|advanced)>/

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
hi def link confInputsStanzas Identifier
hi def link confInputs Keyword
hi def link confInputsConstants Constant
