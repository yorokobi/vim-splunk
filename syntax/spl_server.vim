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
syn keyword confTodo FIXME[:] NOTE[:] TODO[:] contained

" Define generic stanzas
syn match confGenericStanzas display contained /\v[^\]]+/

" Define stanzas
syn region confStanza matchgroup=confStanzaStart start=/^\[/ matchgroup=confStanzaEnd end=/\]/ oneline transparent contains=@confStanzas

" Group clusters
syn cluster confStanzas contains=confServerStanzas,confGenericStanzas

" server.conf
syn match   confServerStanzas contained /\v<(default|general|applic(ationsManagement|ense)|cachemanager|cluster(ing|master:[^]]+))>/
syn match   confServerStanzas contained /\v<(commands:user_configurable|deployment|diag|diskUsage|httpServer(Listener:[^]]+)?|indexer_discovery)>/
syn match   confServerStanzas contained /\v<(introspection:generator:(disk_objects(__(bundle_replication|dispatch|fishbucket|indexes|partitions|summaries|volumes))?))>/
syn match   confServerStanzas contained /\v<(introspection:generator:(kvstore|resource_usage(__iostats)?)|kvstore|license)>/
syn match   confServerStanzas contained /\v<(lmpool:auto_generated_pool_(download_trial|enterprise|fixed-sourcetype_[^]]+|forwarder|free))>/
syn match   confServerStanzas contained /\v<(mimetype-extension-map|parallelreduce|pooling|proxyConfig|pubsubsvr-http|queue(\=[^]]+)?|raft_statemachine)>/
syn match   confServerStanzas contained /\v<(replication_port(-ssl)?:\/\/\d+|scripts|shclustering|sslConfig|std(err|out)_log_rotation)>/

syn match   confServer /\v<^(BackupIndex|acceptFrom|access_logging_for_(heartbeats|phonehome)|acquireExtra_i_data|active_group|adhoc_searchhead)>/
syn match   confServer /\v<^(advertised_disk_capacity|alert_proxying|all_dumps|allow((Basic|Cookie|EmbedToken)Auth|InternetAccess|RemoteLogin|Ssl(Compression|Renegotiation)|_default_empty_p4symmkey|ed_hbmiss_count))>/
syn match   confServer /\v<^(app(License(HostPort|ServerPath)|_update_triggers)|artifact_status_fields|async_replicate_on_proxy|atomFeedStylesheet|auto_rebalance_primaries)>/
syn match   confServer /\v<^(available_sites|backup_and_restore_primaries_in_maintenance|basicAuthRealm|buckets_(per_addpeer|status_notification_batch_size|to_summarize))>/
syn match   confServer /\v<^((busyKeepAliveIdle|distributedLookup|keepAliveIdle|s2sHeartbeat|session|shutdown|streamInWrite|update)Timeout)>/
syn match   confServer /\v<^(ca(Cert(File|Path)|Path)|captain_(is_adhoc_searchhead|uri)|(certCreateScript|checkFrequency|cipherSuite))>/
syn match   confServer /\v<^(cleanRemoteStorageByDefault|cliLoginBanner|(sh)?cluster_label|cntr_(1|2|3)_lookback_time|collection(StatsCollection)?PeriodInSecs)>/
syn match   confServer /\v<^(commit_retry_time|components|compressed|conf_deploy_(concerning_file_size|fetch_(mode|url)|repository|staging))>/
syn match   confServer /\v<^(conf_replication_(include\.[^\ |\=]+|max_(json_value_size|pu(ll|sh)_count)|period|purge\.(eligibile_(age|count)|period)))>/
syn match   confServer /\v<^(conf_replication_summary\.((black|white)list\.[^\ |\=]+|concerning_file_size|period))>/
syn match   confServer /\v<^(connect(UsingIpVersion|ion_timeout)|cookieAuth(HttpOnly|Secure)|crossOriginSharingPolicy|csv_journal_rows_per_hb|cxn_timeout(_raft)?)>/
syn match   confServer /\v<^(dbPath|decommission_(force_finish_idle_time|search_jobs_wait_secs)|dedicatedIoThreads|defaultHTTPServerCompressionLevel)>/
syn match   confServer /\v<^(description|detailsUrl|dh(F|f)ile|disable(d|DefaultPort)|ecdhCurve(s|Name)|election(_timeout_(ms|2_hb_ratio))?)>/
syn match   confServer /\v<^(embedSecret|enable(S2SHeartbeat|SplunkdSSL|_jobs_data_lite)|encrypt_fields|etc_filesize_limit|eviction_policy|(local_)?executor_workers)>/
syn match   confServer /\v<^(follow-symlinks|forceHttp10|forwarder_site_failover|generation_poll_interval|guid|hangup_after_phonehome|heartbeat_(period|timeout))>/
syn match   confServer /\v<^(hostnameOption|hotlist_(bloom_filter_recency_hours|recency_secs)|http(s)?_proxy|id|idle_connections_pool_size|index_(files|listing))>/
syn match   confServer /\v<^(indexerWeightByDiskCapacity|init(Attempts|ialNumberOfScriptProcesses)|instanceType|listenOnIPv6|lock\.(logging|timeout))>/
syn match   confServer /\v<^(log(_age|_heartbeat_append_entries|inUrl)|long_running_jobs_poll_period|maintenance_mode|manual_detention|master_(dump_service_periods|uri))>/
syn match   confServer /\v<^(max(-age|(File)?Size|Sockets|Threads|(_(concurrent_(down|up)loads|content_length|fixup_time_ms|peer_(build|(sum_)?rep)_load|auto_service_interval))))>/
syn match   confServer /\v<^(max_(peers_to_download_bundle|primary_backups_per_service|replication_errors)|mgmt_uri|minFreeSpace|mode|modifications(MaxReadSec|ReadIntervalMillisec))>/
syn match   confServer /\v<^(multisite|no_(artifact_replications|proxy)|notify_scan_(min_)?period|oplogSize|parallelIngestionPipelines|pass(4SymmKey|word))>/
syn match   confServer /\v<^(percent_peers_to_restart|poll\.(blacklist\.[^\ |\=]+|interval\.(check|rebuild))|polling((Timer)?Frequency|_rate)|pool_suggestion)>/
syn match   confServer /\v<^(port|preferred_captain|prefix|prevent_out_of_sync_captain|(profiling|rs|server)StatsCollectionPeriodInSecs|quiet_period|quota|ra_proxying)>/
syn match   confServer /\v<^(raft_rpc_backoff_time_ms|(rcv|send)_timeout(_raft)?|re_add_on_bucket_request_error|rebalance_threshold|(receive|restart)_timeout)>/
syn match   confServer /\v<^(recreate_(bucket_(attempts_from_remote_storage|fetch_manifest_batch_size)|index_(attempts_from_remote_storage|fetch_bucket_batch_size)))>/
syn match   confServer /\v<^(register_(forwarder|replication|search)_address|remote(StorageRecreateIndexesInStandalone|_storage_(retention_period|upload_timeout)))>/
syn match   confServer /\v<^(rep_(cxn|max_(rcv|send)|rcv|send)_timeout|replica(set|te_search_peers|tionWriteTimeout|tion_(factor|host))|replyHeader\.[^\ |\=]+)>/
syn match   confServer /\v<^(report_interval|require(BootPassphrase|ClientCert)|retry_autosummarize_or_data_model_acceleration_jobs|rolling_restart_with_captaincy_exchange)>/
syn match   confServer /\v<^(rootCA|sampling_interval|scheduling_heuristic|search_(factor|files_retry_timeout)|sid_proxying|site(_mappings|_(replication|search)_factor)?)>/
syn match   confServer /\v<^(searchable_(targets|target_sync_timeout)|sendStrictTransportSecurityHeader|server(Cert|Name)|servers_list|service_(interval|jobs_msec))>/
syn match   confServer /\v<^(skipHTTPCompressionAcl|slaves|squash_threshold|ss_proxying|ssl)>/
syn match   confServer /\v<^(ssl(AltNameToCheck|CRLPath|ClientSessionPath|CommonName(List|ToCheck)|Keys(Password|Path|file(Password)?)|Password|RootCAPath|ServerSessionTimeout|VerifyServerCert|Versions(ForClient)?))>/
syn match   confServer /\v<^(stack_id|state(IntervalInSecs)?|storage|strict_pool_quota|summary_(registration_batch_size|replication|update_batch_size|wait_time))>/
syn match   confServer /\v<^(supportSSLV3Only|tar_format|target_wait_time|throwOnBucketBuildReadError|trustedIP|update(Host|Path)|upload_proto_host_port|url)>/
syn match   confServer /\v<^(use(((Splunkd)?ClientSSL|HTTP(Client|Server)|SSL)Compression|SslClientSessionCache)|use_batch_mask_changes|useragent|verbose(Level)?)>/
syn match   confServer /\v<^(x_frame_options_sameorigin)>/

syn match   confServerConstants /\v<(Enterprise|Trial|Forwarder|Free|always|never|requireSetPassword|silent|primaries(_and_hot)?|all|auto|replace|none)$>/
syn match   confServerConstants /\v<((4|6)-(first|only)|full|manifests|light|no|yes|only|on_ports_enabled|self|(dis|en)abled|searchhead|slave|master|MAX)$>/
syn match   confServerConstants /\v<((gnu|us)tar|on-http(s)?)$>/

syn match   confComplex /\v<^((EXCLUDE|SEARCHFILTER(LUHN|SIMPLE))-\w+)>/

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
hi def link confServerStanzas Identifier
hi def link confServer Keyword
hi def link confServerConstants Constant
hi def link confComplex Preproc
