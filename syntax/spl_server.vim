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
syn match   confServer /\v<^(dbPath|decommission_(force_finish_idle_time|search_jobs_(min_wait_ratio|wait_secs))|dedicatedIoThreads|defaultHTTPServerCompressionLevel)>/
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
syn match   confServerConstants /\v<((gnu|us)tar|on-http(s)?|site([1-5]?[0-9]|6[0-3]))$>/

" ----------
"  7.1
" ----------
syn match   confServer /\v<^(rolling_restart|site_by_site|(decommission_force|restart_inactivity)_timeout|reporting_delay_period)>/
syn match   confServer /\v<^(conf_replication_find_baseline\.use_bloomfilter_only|eviction_padding|max_size_kb)>/

syn match   confServerConstants /\v<(restart|shutdown|searchable(_force)?)$>/
syn match   confComplex /\v<^((EXCLUDE|SEARCHFILTER(LUHN|SIMPLE))-\w+)>/

" 7.2.3
syn match   confServer /\v<^(legacyCiphers|splunkd_stop_timeout|sslRootCAPathHonoredOnWindows|decommission_node_force_timeout)>/
syn match   confServer /\v<^(constrain_singlesite_buckets|max_nonhot_rep_kBps|signatureVersion|enable_eviction_priorities|token)>/
syn match   confServer /\v<^(max_cache_size|responseTimeout|actions(Interval)?|pstacksEndpoint|reaperThread|dumpAllThreads)>/
syn match   confServer /\v<^(stacksBufferSizeOrder|maxStacksPerBlock|path|useShell|forceStop(OnShutdown)?|uri|refresh_interval)>/
syn match   confServer /\v<^(remote\.s3\.header\.(GET|PUT|ALL)\.\S+|remote\.s3\.(access|secret)_key)>/
syn match   confServer /\v<^(remote\.s3\.((list_objects|signature)_version|auth_region|use_delimiter|endpoint))>/
syn match   confServer /\v<^(remote\.s3\.(supports_versioning|retry_policy|multipart_(up|down)load\.part_size))>/
syn match   confServer /\v<^(remote\.s3\.(multipart_max_connections|max_count\.max_retries_(per_part|in_total)))>/
syn match   confServer /\v<^(remote\.s3\.(timeout\.(connect|read|write)|ssl(VerifyServerCert|Versions|(Common|Alt)NameToCheck|RootCAPath)))>/
syn match   confServer /\v<^(remote\.s3\.(cipherSuite|ecdhCurves|dhFile|encryption(\.sse-(s3|c\.key_(type|refresh_interval)))?))>/
syn match   confServer /\v<^(remote\.s3\.kms\.(key_id|(access|secret)_key|auth_region|max_concurrent_requests|cipherSuite))>/
syn match   confServer /\v<^(remote\.s3\.kms\.ssl(VerifyServerCert|Versions|RootCAPath|(Alt|Common)NameToCheck))>/
syn match   confServer /\v<^(remote\.s3\.kms\.(ecdhCurves|dhFile))>/
syn match   confServerConstants /\v<(decryptOnly|max_count|sse-(s3|kms|c)|kms)$>/
syn match   confServerStanzas contained /\v<(node_auth|watchdog(:timeouts)?|watchdogaction:(pstacks|script)|(rendezvous|bucket_catalog)_service)>/
syn match   confServerStanzas contained /\v<(search_artifact_remote_storage)>/

" 7.3.0
syn match   confServerStanzas contained /\v<(dfs(_security)?|introspection:distributed-indexes|app_backup)>/

syn match   confServer /\v<^(pipelineSet(SelectionPolicy|WeightsUpdatePeriod|NumTrackingPeriods)|sslServerHandshakeTimeout)>/
syn match   confServer /\v<^(tls_(enabled|protocol)|override_default_certificate|use_(spark_security_configs|node_specific_certificates))>/
syn match   confServer /\v<^(verify_search_peer_to_dfw_client_certificate|legacy_ca_certificate_folder|dfs_(key|trust)store_path)>/
syn match   confServer /\v<^(search_peer_to_dfw_(common|alt)_name_list|df(c|s|w)_(key|trust)store_password|df(c|s|w)_key_password|df(c|w)_(key|trust)store_path)>/
syn match   confServer /\v<^(proxy_rules|deferred_cluster_status_update|backup_path)>/
syn match   confServer /\v<^(rebalance_(pipeline_batch_size|(primary_failover|newgen_propagation|search_completion)_timeout)|searchable_rebalance)>/
syn match   confServer /\v<^(use_batch_remote_rep_changes|operationStatsCollectionPeriodInSecs)>/
syn match   confServer /\v<^(dfc_ip_address|extra_kryo_registered_classes|spark_master_(host|webui_port|connect_timeout)|spark_home|connection_retries)>/
syn match   confServer /\v<^(persist(_pending_upload_from_external|ent_id_set_remove_min_sync_secs)|enable_open_on_stale_object)>/
syn match   confServer /\v<^(batchStacksThreshold)>/

syn match   confServerConstants /\v<(cluster(manager|master):\S+)$>/

" 8.1.0
syn match   confServerStanzas contained /\v<(cascading_replication|cache_manager_service|hot_bucket_streaming)>/

syn match   confServer /\v<^(pass4SymmKey_minLength|pipelineSetChannelSetCacheSize|numThreadsForIndexInitExecutor|numThreadsForIndexInitExecutor)>/
syn match   confServer /\v<^(python\.version|roll_and_wait_for_uploads_at_shutdown_secs|crossOriginSharingHeaders|freeze_during_maintenance)>/
syn match   confServer /\v<^(dedicatedIoThreads(SelectionPolicy|WeightsUpdatePeriod)|license_warnings_update_interval|assign_primaries_to_all_sites)>/
syn match   confServer /\v<^(service_execution_threshold_ms|deferred_rest_api_update|max_delayed_updates_time_ms|commit_generation_execution_limit_ms)>/
syn match   confServer /\v<^(rolling_restart_condition|streaming_replication_wait_secs|rebalance_primaries_execution_limit(_ms)?)>/
syn match   confServer /\v<^(bucketsize_mismatch_strategy|report_remote_storage_bucket_upload_to_targets|recreate_bucket_max_per_service)>/
syn match   confServer /\v<^(max_(peer_batch_rep_load|concurrent_peers_joining)|enable_(parallel_add_peer|primary_fixup_during_maintenance))>/
syn match   confServer /\v<^(log_bucket_during_addpeer|notify_buckets_period|warm_bucket_replication_pre_upload|bucketsize_upload_preference|upload_rectifier_timeout_secs)>/
syn match   confServer /\v<^(collectLocalIndexes|deployerPushThreads|storageEngine(Migration)?|clientConnection(Timeout|PoolSize)|clientSocketTimeout)>/
syn match   confServer /\v<^(initialSyncMaxFetcherRestarts|delayShutdownOnBackupRestoreInProgress|percRAMForCache|local_delete_summary_metadata_ttl)>/
syn match   confServer /\v<^(max_replication_(threads|jobs)|cascade_replication_plan_(age|fanout|reap_interval|topology|select_policy))>/
syn match   confServer /\v<^(evict_on_stable|max_file_exists_retry_count|access_logging|cache_usage_collection_(interval_minutes|time_bins|per_index))>/
syn match   confServer /\v<^(batch_registration(_size)?|ping_enabled|timeout\.(ping|connect|read|write)|upload_archive_format)>/
syn match   confServer /\v<^(slices_list_executor_workers|slices_(download|build|removal|upload)_executor_workers)>/
syn match   confServer /\v<^(slices_upload_executor_capacity|slices_upload_send_interval|slices_upload_size_threshold)>/
syn match   confServer /\v<^()>/

syn match   confServerConstants /\v<(python(2|3)?|force_python3|weighted_random|round_robin|up|batch_adding|starting)$>/
syn match   confServerConstants /\v<(smallest|largest|mmapv1|wiredTiger|size_balanced|random|none|tar\.lz4)$>/

" 8.2
syn match   confServer /\v<^(preShutdownCleanup|reset_manifests_on_startup|percent_manifests_to_reset|regex_cache_hiwater)>/
syn match   confServer /\v<^(allowWwwAuthHeader|cookieSameSiteSecure|imds_version|manager_uri)>/
syn match   confServer /\v<^(primary_src_persist_secs|searchable_rolling_(peer_state_delay_interval|site_down_policy))>/
syn match   confServer /\v<^(percent_peers_to_reload|precompress_cluster_bundle|precompress_artifacts)>/
syn match   confServer /\v<^(conf_deploy_precompress_bundles|cache_upload_backoff_sleep_secs|max_known_remote_absent_summaries)>/
syn match   confServer /\v<^(usePreloadedPstacks|scsTokenScriptPath)>/

syn match   confServerConstants /\v<((fullyqualified|cluster|short)name|track-only|v(1|2|4)|peer|manager|most|half)$>/

syn match   confServerStanzas contained /\v<(imds|clustermanager:\S+|federated_search|distributed_leases)>/

" 9.0.0
syn match   confServerStanzas contained /\v<(config_change_tracker|pythonSslClientConfig|search_state|manager_pages)>/

syn match   confServer /\v<^(denylist|log_throttling_(disabled|threshold_ms)|exclude_fields|sslVerifyServerName)>/
syn match   confServer /\v<^(certificateStatusValidationMethod|cliVerifyServerName|peers|manager_switchover_(mode|quiet_period))>/
syn match   confServer /\v<^(cm_(heartbeat_period|max_hbmiss_count|com_timeout)|ack_factor|captain_dump_service_periods)>/
syn match   confServer /\v<^(conf_replication_summary.(in|ex)cludelist.\k+|remote_job_retry_attempts|remote.s3.kms.ssl\k+)>/
syn match   confServer /\v<^(slices_upload_retry_pending|transparent_mode|whole_search_execution_optimization|(sends|receives)DeltaBundle)>/
syn match   confServer /\v<^(syncProxyBundleToClusterMembers|(alert|suppression)_store|sanitize_uri_param)>/
syn match   confServer /\v<^(invalidateSessionTokensOnLogout|logoutCacheRefreshInterval|enable_encrypt_bundle)>/
syn match   confServer /\v<^(remote\.s3\.header\.(POST|GET)\.\k+)>/

syn match   confServerConstants /\v<(crl|manual)$>/

" 9.1.0
syn match   confServer /\v<^(enable_search_process_long_lifespan|conf_generation_include\.\k+|mgmtMode)>/
syn match   confServer /\v<^(lm_(uri|ping_interval)|generation_max_staleness|localization_(based_primary_selection|update_batch_size))>/
syn match   confServer /\v<^(allow_concurrent_dispatch_savedsearch)>/
syn match   confServer /\v<^()>/

syn match   confServerConstants /\v<(tcp)$>/

" 9.3.0
syn match   confServerStanzas contained /\v<(teleport_supervisor|localProxy)>/
syn match   confServerConstants /\v<(python3\.(7|9)|force_python3|unspecified|splunk|OS)$>/
syn match   confServer /\v<^(unbiasLanguageForLogging|is_remote_queue_accounting_batched|conf_cache_memory_optimization)>/
syn match   confServer /\v<^(cgroup_location|caTrustStore(Path)?|auto_fix_corrupt_buckets|remote_storage_freeze_delay_period)>/
syn match   confServer /\v<^(notify_buckets_usage_(period|batch_size)|max_usage_rebalance_(retries|operations_per_service))>/
syn match   confServer /\v<^(bucket_usage_decay_half_life|usage_rebalance_bucket_movement_factor)>/
syn match   confServer /\v<^(jobs_data_lite\.(enabled|exclude_fields|(search|default)_field_len|max_status_size_per_hb))>/
syn match   confServer /\v<^(cache_upload_bucket_has_priority|max_concurrent_requests|response_timeout_ms)>/

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
