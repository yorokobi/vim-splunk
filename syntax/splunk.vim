" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>
" Last Change: 2014 Nov 08 10:53 UTC-7
" Contributor: pi-rho <https://github.com/pi-rho>

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
syn match confSpecComment /^\s*\*.*/ contains=confTodo oneline display

syn region confString start=/"/ skip="\\\"" end=/"/ oneline display contains=confNumber,confVar
syn region confString start=/`/             end=/`/ oneline display contains=confNumber,confVar
syn region confString start=/'/ skip="\\'"  end=/'/ oneline display contains=confNumber,confVar
syn match  confNumber /\v[+-]?\d+([ywdhs]|m(on|ins?))(\@([ywdhs]|m(on|ins?))\d*)?>/
syn match  confNumber /\v[+-]?\d+(\.\d+)*>/
syn match  confNumber /\v<\d+[TGMK]B>/
syn match  confPath   ,\v(^|\s|\=)\zs(file:|https?:|\$\k+)?(/+\k+)+(:\d+)?,
syn match  confPath   ,\v(^|\s|\=)\zsvolume:\k+(/+\k+)+,
syn match  confVar    /\$\k\+\$/

syn keyword confBoolean on off t[rue] f[alse] T[rue] F[alse]
syn keyword confTodo FIXME NOTE TODO contained

" Define stanzas
syn region confStanza matchgroup=confStanzaStart start=/^\[/ matchgroup=confStanzaEnd end=/\]/ oneline transparent contains=@confStanzas

" Group clusters (incomplete)
syn cluster confStanzas contains=confAlertActionsStanzas,confAppStanzas,confAuditStanzas,confAuthenticationStanzas,confAuthorizeStanzas,confCommandsStanzas,confCrawlStanzas,confDataModelsStanzas,confDefmodeStanzas,confDeployClientStanzas,confDistSearchStanzas,confEventGenStanzas,confEventRenderStanzas,confEventDiscoverStanzas,confEventTypesStanzas,confFieldsStanzas,confIndexesStanzas,confInputsStanzas,confLimitsStanzas,confOutputsStanzas,confPDFserverStanzas,confPropsStanzas,confPubsubStanzas,confRegmonFiltersStanzas,confRestmapStanzas,confSavedSearchesStanzas,confSegmenterStanzas,confServerStanzas,confServerClassStanzas,confSourceTypesStanzas,confTenantsStanzas,confTimesStanzas,confTransactionTypesStanzas,confTransformsStanzas,confUIPrefsStanzas,confUserSeedStanzas,confViewStatesStanzas,confWebStanzas,confWmiStanzas,confWorkflowActionsStanzas,confGenericStanzas,confMetaStanzas,confSearchbnfStanzas,confCollectionsStanzas,confDataTypesbnfStanzas,confUserPrefsStanzas 

syn match confGenericStanzas display contained /\v[^\]]+/

" admon.conf
syn keyword confADmon targetDc startingNode monitorSubtree disabled index

" alert_actions.conf
syn match   confAlertActionsStanzas contained /\v<(default|email|rss|script|summary_index|populate_lookup)>/
syn keyword confAlertActions maxresults hostname ttl maxtime track_alert command
syn keyword confAlertActions from to cc bcc subject format sendresults inline
syn keyword confAlertActions mailserver use_ssl use_tls auth_username auth_password
syn keyword confAlertActions sendpdf pdfview reportServerEnabled reportServerURL
syn keyword confAlertActions reportPaperSize reportPaperOrientation reportIncludeSplunkLogo
syn keyword confAlertActions reportCIDFontList width_sort_columns preprocess_results
syn keyword confAlertActions items_count filename _name dest subject.alert subject.report useNSSubject message.report message.alert footer.text
syn keyword confAlertActions include.results_link include.view_link include.search include.trigger include.trigger_time
syn keyword confAlertActions sendcsv priority inline

" app.conf
syn match   confAppStanzas contained /\v<(launcher|package|install|triggers|ui|credentials_settings|credential:[^\]]+)>/
syn keyword confApp remote_tab version description author id check_for_updates docs_section_override
syn keyword confApp state state_change_requires_restart is_configured build allows_disable
syn keyword confApp reload. is_visible is_manageable label verify_script password
syn keyword confApp install_source_checksum docs_section_override

" audit.conf
syn match   confAuditStanzas contained /\v<(event(Hash|Sign)ing|auditTrail|filterSpec:[^\]]+)>/
syn keyword confAudit filters all source host sourcetype privateKey publicKey queueing

" authentication.conf
syn match   confAuthenticationStanzas contained /\v<(authentication|cacheTiming|splunk_auth|roleMap_[^\]]+)>/
syn keyword confAuthentication admin authType authSettings host SSLEnabled port bindDN bindDNpassword
syn keyword confAuthentication userBaseDN userBaseFilter userNameAttribute realNameAttribute
syn keyword confAuthentication groupMappingAttribute groupBaseDN groupBaseFilter dynamicGroupFilter
syn keyword confAuthentication dynamicMemberAttribute groupNameAttribute groupMemberAttribute
syn keyword confAuthentication nestedGroups charset anonymous_referrals sizelimit timelimit
syn keyword confAuthentication network_timeout scriptPath Scripted scriptSearchFilters user userLoginTTL
syn keyword confAuthentication getUserInfoTTL getUsersTTL passwordHashAlgorithm power emailAttribute
syn keyword confAuthentication minPasswordLength

" authorize.conf
syn match   confAuthorizeStanzas contained /\v<(default|(capability::|role_)[^\]]+)>/
syn keyword confAuthorize importRoles grantableRoles srchFilter srchTimeWin srchDiskQuota srchJobsQuota
syn keyword confAuthorize rtSrchJobsQuota srchMaxTime srchIndexesDefault srchIndexesAllowed
syn keyword confAuthorize cumulativeSrchJobsQuota cumulativeRTSrchJobsQuota rtsearch

" collections.conf
syn match   confCollectionsStanzas contained /\v[^\]]+/
syn keyword confCollections enforceTypes field. accelerated_fields. profilingEnabled profilingThresholdMs

" commands.conf
syn match   confCommandsStanzas contained /\v<(default)>/
syntax case ignore
syn keyword confCommands type filename local perf_warn_limit streaming maxinputs passauth
syn keyword confCommands run_in_preview enableheader retainsevents generating generates_timeorder
syn keyword confCommands overrides_timeorder requires_preop streaming_preop required_fields
syn keyword confCommands supports_multivalues supports_getinfo supports_rawargs undo_scheduler_escaping
syn keyword confCommands requires_srinfo needs_empty_results changes_colorder clear_required_fields
syn keyword confCommands stderr_dest outputheader
syntax case match

" crawl.conf
syn match   confCrawlStanzas contained /\v<(default|files|network)>/
syn keyword confCrawl root bad_directories_list bad_extensions_list bad_file_matches_list packed_extensions_list
syn keyword confCrawl collapse_threshold days_sizek_pairs_list big_dir_filecount index max_badfiles_per_dir
syn keyword confCrawl host subnet

" datamodels.conf
syn match   confDataModelsStanzas contained /\v<(default)>/
syn keyword confDataModels acceleration acceleration.earliest_time acceleration.backfill_time 
syn keyword confDataModels acceleration.max_time acceleration.cron_schedule acceleration.manual_rebuilds

" datatypesbnf.conf
syn match   confDataTypesbnfStanzas contained /\v[^\]]+/
syn keyword confDataTypesbnf syntax

" default-mode.conf
syn match   confDefModeStanzas contained /\v<(pipeline:[^\]]+)>/
syn keyword confDefMode disabled disabled_processors

" deploymentclient.conf
syn match   confDeployClientStanzas contained /\v<(default|deployment-client|target-broker:deploymentServer)>/
syn keyword confDeployClient disabled clientName workingDir repositoryLocation
syn keyword confDeployClient serverRepositoryLocationPolicy endpoint serverEndpointPolicy
syn keyword confDeployClient phoneHomeIntervalInSecs handshakeRetryIntervalInSecs
syn keyword confDeployClient reloadDSOnAppInstall targetUri

" distsearch.conf
syn match   confDistSearchStanzas contained /\v<(default|distributedSearch(:[^\]]+)?|tokenExchKeys|searchhead:[^\]]+)>/
syn match   confDistSearchStanzas contained /\v<replication(Settings(:refineConf)?|(White|Black)list)>/
syn match   confDistSearchStanzas contained /\v<bundleEnforcer(White|Black)list>/
syn keyword confDistSearch disabled heartbeatMcastAddr heartbeatPort ttl heartbeatFrequency
syn keyword confDistSearch statusTimeout removedTimedOutServers checkTimedOutServersFrequency
syn keyword confDistSearch autoAddServers bestEffortSearch skipOurselves servers disabled_servers
syn keyword confDistSearch shareBundles useSHPBundleReplication serverTimeout connectionTimeout
syn keyword confDistSearch sendTimeout receiveTimeout certDir publicKey privateKey genKeyScript
syn keyword confDistSearch connectionTimeout sendRcvTimeout replicationThreads maxMemoryBundleSize
syn keyword confDistSearch maxBundleSize concerningReplicatedFileSize allowStreamUpload
syn keyword confDistSearch allowSkipEncoding allowDeltaUpload sanitizeMetaFiles
syn keyword confDistSearch replicate. mounted_bundles bundles_location trySSLFirst peerResolutionThreads
syn keyword confDistSearch authTokenConnectionTimeout authTokenSendTimeout authTokenReceiveTimeout allConf
syn keyword confDistSearch servers default

" eventdiscoverer.conf
syn match   confEventDiscoverStanzas contained /\v<(default)>/
syn keyword confEventDiscover ignored_keywords ignored_fields important_keywords

" event_renderers.conf
syn match   confEventRenderStanzas contained /\v<(default)>/
syn keyword confEventRender eventtype priority template css_class

" eventgen.conf
syn match   confEventGenStanzas contained /\v<(default|global)>/
syn keyword confEventGen spoolDir spoolFile interval count earliest latest breaker token replacementType
syn keyword confEventGen replacement

" eventtypes.conf
syn match   confEventTypesStanzas contained /\v<(default>|\k+-\%\k+\%)/
syn keyword confEventTypes disabled search priority description tags

" fields.conf
syn match   confFieldsStanzas contained /\v<(default)>/
syn keyword confFields TOKENIZER INDEXED INDEXED_VALUE

" indexes.conf
syn match   confIndexesStanzas contained /\v<(default|volume:[^\]]+)>/
syn keyword confIndexes sync defaultDatabase queryLanguageDefinition blockSignatureDatabase
syn keyword confIndexes memPoolMB indexThreads assureUTF8 enableRealtimeSearch suppressBannerList
syn keyword confIndexes maxRunningProcessGroups maxRunningProcessGroupsLowPriority bucketRebuildMemoryHint
syn keyword confIndexes serviceOnlyAsNeeded serviceSubtaskTimingPeriod maxBucketSizeCacheEntries
syn keyword confIndexes tsidxStatsHomePath disabled deleted homePath coldPath thawedPath
syn keyword confIndexes bloomHomePath createBloomfilter summaryHomePath maxBloomBackfillBucketAge
syn keyword confIndexes enableOnlineBucketRepair maxWarmDBCount maxTotalDataSizeMB
syn keyword confIndexes rotatePeriodInSecs frozenTimePeriodInSecs warmToColdScript
syn keyword confIndexes coldToFrozenScript coldToFrozenDir compressRawdata maxConcurrentOptimizes
syn keyword confIndexes maxDataSize rawFileSizeBytes rawChunkSizeBytes minRawFileSyncSecs maxMemMB
syn keyword confIndexes blockSignSize maxHotSpanSecs maxHotIdleSecs maxHotBuckets quarantinePastSecs
syn keyword confIndexes quarantineFutureSecs maxMetaEntries syncMeta serviceMetaPeriod
syn keyword confIndexes partialServiceMetaPeriod throttleCheckPeriod maxTimeUnreplicatedWithAcks
syn keyword confIndexes maxTimeUnreplicatedNoAcks isReadOnly homePath.maxDataSizeMB coldPath.maxDataSizeMB
syn keyword confIndexes disableGlobalMetadata repFactor path maxVolumeDataSizeMB rotatePeriodInSecs
syn keyword confIndexes inPlaceUpdates processTrackerServiceInterval tstatsHomePath minStreamGroupQueueSize
syn keyword confIndexes hotBucketTimeRefreshInterval streamingTargetTsidxSyncPeriodMsec
syn keyword confIndexes_Constants auto_high_volume auto disable

" inputs.conf
syn match   confInputsStanzas contained /\v<(tcp(-ssl)?|splunktcp(-ssl)?|monitor|batch|udp|fifo|script|fschange|filter|WinEventLog|(ad|perf)mon):[^\]]+>/
syn match   confInputsStanzas contained /\v<(default|SSL|splunktcp)>/
syn keyword confInputs host index source sourcetype queue _TCP_ROUTING _SYSLOG_ROUTING _raw _meta _time
syn keyword confInputs host_regex host_segment crcSalt initCrcLength ignoreOlderThan
syn keyword confInputs whitelist blacklist _whitelist _blacklist
syn keyword confInputs followTail alwaysOpenFile time_before_close recursive followSymlink dedicatedFD
syn keyword confInputs move_policy connection_host queueSize persistentQueueSize
syn keyword confInputs requireHeader listenOnIPv6 acceptFrom rawTcpDoneTimeout route compressed
syn keyword confInputs enableS2SHeartbeat s2sHeartbeatTimeout inputShutdownTimeout
syn keyword confInputs serverCert password rootCA requireClientCert supportSSLV3Only cipherSuite
syn keyword confInputs _rcvbuf no_priority_stripping no_appending_timestamp interval passAuth
syn keyword confInputs signedaudit filters recurse followLinks pollPeriod hashMaxSize fullEvent
syn keyword confInputs sendEventMaxSize filesPerDelay delayInMills regex
syn keyword confInputs disabled start_from current_only checkpointInterval evt_resolve_ad_obj evt_dc_name
syn keyword confInputs evt_dns_name _INDEX_AND_FORWARD_ROUTING negotiateNewProtocol concurrentChannelLimit
syn keyword confInputs allowSslRenegotiation start_by_shell object counters instances samplingInterval stats showZeroValue
syn keyword confInputs suppress_text printSchema remoteAddress process user addressFamily packetType direction
syn keyword confInputs protocol readInterval driverBufferSize userBufferSize multikvMaxEventCount multikvMaxTimeMs
syn keyword confInputs table output.format output.timestamp output.timestamp.column output.timestamp.format
syn keyword confInputs stopAcceptorAfterQBlock sslVersions ecdhCurveName sslQuietShutdown send_index_as_argument_for_path
syn keyword confInputs mode useEnglishOnly renderXml targetDc startingNode monitorSubtree printSchema baseline proc
syn keyword confInputs hive type baseline_interval
syn keyword confInputs whitelist1 whitelist2 whitelist3 whitelist4 whitelist5 whitelist6 whitelist7 whitelist8 whitelist9
syn keyword confInputs blacklist1 blacklist2 blacklist3 blacklist4 blacklist5 blacklist6 blacklist7 blacklist8 blacklist9
syn keyword confInputs_Constants parsingQueue indexQueue

" limits.conf
syn match   confLimitsStanzas contained /\v<(anomalousvalue|associate|authtokens|auto_summarizer|autoregress|concurrency)>/
syn match   confLimitsStanzas contained /\v<(correlate|ctable|default|discretize|export|extern|indexpreview)>/
syn match   confLimitsStanzas contained /\v<(input(_channels|csv|proc)|join|journal_compress|kmeans|kv|ldap|lookup)>/
syn match   confLimitsStanzas contained /\v<(metadata|metrics|pdf|rare|realtime|restapi|reversedns|sample|scheduler)>/
syn match   confLimitsStanzas contained /\v<(search(results)?|set|show_source|sistats|slc|sort|spath|stats|subsearch)>/
syn match   confLimitsStanzas contained /\v<(summarize|thruput|top|transactions|tscollect|typeahead|typer|viewstates)>/
syn keyword confLimits max_mem_usage_mb maxresultrows tocsv_maxretry tocsv_retryperiod_ms maxout
syn keyword confLimits maxtime ttl maxvalues maxvaluesize maxfields maxp maxrange
syn keyword confLimits max_count maxbins add_timestamp add_offset perf_warn_limit mkdir_max_retries
syn keyword confLimits max_preview_bytes max_results_perchunk soft_preview_queue_size suppress_derived_info
syn keyword confLimits subsearch_maxout subsearch_maxtime subsearch_timeout maxdatapoints maxkvalue
syn keyword confLimits maxkrange maxcols limit maxchars max_extractor_time avg_extractor_time max_lookup_messages
syn keyword confLimits max_memtable_bytes max_matches max_reverse_matches batch_index_query aggregate_metrics
syn keyword confLimits batch_response_limit maxseries interval time_format_reject jobscontentmaxcount
syn keyword confLimits summary_mode use_bloomfilter ttl default_save_ttl remote_ttl status_buckets result_queue_max_size
syn keyword confLimits max_bucket_bytes max_events_per_bucket truncate_report min_prefix_len debug_metrics
syn keyword confLimits max_results_raw_size cache_ttl min_results_perchunk max_rawsize_perchunk
syn keyword confLimits target_time_perchunk long_search_threshold chunk_multiplier min_freq reduce_freq
syn keyword confLimits reduce_duty_cycle preview_duty_cycle dispatch_quota_retry dispatch_quota_sleep_ms
syn keyword confLimits base_max_searches max_searches_per_cpu max_rt_search_multiplier max_macro_depth
syn keyword confLimits realtime_buffer stack_size status_cache_size timeline_freq preview_freq
syn keyword confLimits max_combiner_memevents replication_period_sec sync_bundle_replication
syn keyword confLimits multi_threaded_setup rr_min_sleep_ms rr_max_sleep_ms rr_sleep_factor
syn keyword confLimits fieldstats_update_freq fieldstats_update_maxperiod remote_timeline results_queue_min_size
syn keyword confLimits remote_timeline_min_peers remote_timeline_fetchall remote_timeline_thread
syn keyword confLimits remote_timeline_max_count remote_timeline_max_size_mb remote_timeline_touchperiod
syn keyword confLimits remote_timeline_connection_timeout remote_timeline_send_timeout
syn keyword confLimits remote_timeline_receive_timeout default_allow_queue queued_job_check_freq
syn keyword confLimits enable_history max_history_length allow_inexact_metasearch indexed_as_exact_metasearch
syn keyword confLimits dispatch_dir_warning_size allow_reuse track_indextime_range reuse_map_maxsize
syn keyword confLimits use_dispatchtmp_dir status_period_ms search_process_mode fetch_remote_search_log
syn keyword confLimits load_remote_bundles check_splunkd_period queue_size blocking max_blocking_secs
syn keyword confLimits indexfilter default_backfill list_maxsize enforce_time_order disk_usage_update_period
syn keyword confLimits maxclusters sparkline_maxsize maxfiles maxmem_check_freq rdigest_k
syn keyword confLimits rdigest_maxnodes max_stream_window max_valuemap_bytes perc_method approx_dc_threshold
syn keyword confLimits dc_digest_bits natural_sort_output maxKBps threads hot_bucket_min_new_events
syn keyword confLimits sleep_seconds stale_lock_seconds max_summary_ratio max_summary_size max_time
syn keyword confLimits indextime_lag maxopentxn maxopenevents max_fd time_before_close tailing_proc_speed
syn keyword confLimits max_searches_perc auto_summary_perc max_action_results action_execution_threads
syn keyword confLimits actions_queue_size actions_queue_timeout alerts_max_count alerts_expire_period
syn keyword confLimits persistance_period max_lock_files max_lock_file_ttl max_per_result_alerts
syn keyword confLimits max_per_result_alerts_time scheduled_view_timeout cache_timeout
syn keyword confLimits maintenance_period allow_event_summarization max_verify_buckets max_verify_ratio
syn keyword confLimits max_verify_bucket_time verify_delete max_verify_total_time max_run_stats
syn keyword confLimits max_timebefore max_timeafter distributed distributed_search_limit maxcount
syn keyword confLimits use_cache fetch_multiplier cache_ttl_sec min_prefix_length max_concurrent_per_user
syn keyword confLimits maxlen expiration_time maxsamples maxtotalsamples max_inactive lowater_inactive
syn keyword confLimits inactive_eligibility_age_seconds max_users_to_precache allow_multiple_matching_users
syn keyword confLimits extraction_cutoff extract_all rdnsMaxDutyCycle enable_reaper reaper_freq
syn keyword confLimits reaper_soft_warn_level squashcase keepresults tsidx_init_file_goal_mb
syn keyword confLimits optimize_period optimize_min_src_count optimize_max_size_mb
syn keyword confLimits max_rows_per_table render_endpoint_timeout min_batch_size_bytes default_time_bins
syn keyword confLimits max_id_length replication_file_ttl remote_timeline_prefetch remote_timeline_parallel_fetch
syn keyword confLimits allow_batch_mode batch_search_max_index_values batch_retry_min_interval batch_retry_max_interval
syn keyword confLimits batch_wait_after_end write_multifile_results_out enable_cumulative_quota local_connect_timeout
syn keyword confLimits local_send_timeout local_receive_timeout indexed_realtime_use_by_default indexed_realtime_disk_sync_delay
syn keyword confLimits indexed_realtime_default_span indexed_realtime_maximum_span indexed_realtime_cluster_update_interval
syn keyword confLimits default_partitions partitions_limit return_actions_with_normalized_ids normalized_summaries
syn keyword confLimits detailed_dashboard maxzoomlevel zl_0_gridcell_latspan zl_0_gridcell_longspan filterstrategy
syn keyword confLimits apply_search_filter summariesonly compression_level max_infocsv_messages infocsv_log_level
syn keyword confLimits alerting_period_ms allow_old_summaries batch_retry_scaling chunk_size db_path enable_status_cache
syn keyword confLimits file_tracking_db_threshold_mb max_accelerations_per_collection max_chunk_queue_size
syn keyword confLimits max_documents_per_batch_save max_fields_per_acceleration max_queries_per_batch max_rows_per_query
syn keyword confLimits max_size_per_batch_result_mb max_size_per_batch_save_mb max_size_per_result_mb max_tolerable_skew
syn keyword confLimits max_workers_searchparser remote_reduce_limit search_2_hash_cache_timeout shc_accurate_access_counts
syn keyword confLimits shp_dispatch_to_slave status_cache_in_memory_ttl

" macros.conf
"syn keyword confMacrosStanzas
syn keyword confMacros args definition validation errormsg iseval description

" *.meta
syn match confMetaStanzas contained /\v<(views(\/[^\]]+)?|transforms|exports|savedsearches|macros|eventtypes)>/
syn keyword confMeta access export owner
syn keyword confMeta_Constants system admin power read write none

" multikv.conf
"syn keyword confMultikvStanzas
syn match   confMultikv /\v<(pre|header|body|post)\.(start(_offset)?|end|member|linecount|ignore|replace|tokens)>/
syn keyword confMultikv _chop_ _tokenize_ _align_ _token_list_ _regex_ _all_

" outputs.conf
syn match   confOutputsStanzas contained /\v<(default|tcpout((-server)?:[^\]]+)?|syslog(:[^\]]+)?|indexAndForward)>/
syn keyword confOutputs defaultGroup indexAndForward server sendCookedData heartbeatFrequency
syn keyword confOutputs blockOnCloning compressed maxQueueSize dropEventsOnQueueFull dropClonedEventsOnQueueFull
syn keyword confOutputs maxFailuresPerInterval secsInFailureInterval maxConnectionsPerIndexer
syn keyword confOutputs connectionTimeout readTimeout writeTimeout dnsResolutionInterval
syn keyword confOutputs forceTimebasedAutoLB forwardedindex. autoLBFrequency .whitelist .blacklist
syn keyword confOutputs forwardedindex.filter.disable autoLB sslPassword sslCertPath sslRootCAPath
syn keyword confOutputs sslVerifyServerCert sslCommonNameToCheck sslAltNameToCheck useClientSSLCompression
syn keyword confOutputs useACK type priority syslogSourceType timestampformat selectiveIndexing
syn keyword confOutputs masterUri blockWarnThreshold negotiateNewProtocol channelReapInterval channelTTL
syn keyword confOutputs channelReapLowater backoffOnFailure maxEventSize

" pdf_server.conf
syn match   confPDFserverStanzas contained /\v<(settings)>/
syn keyword confPDFserver startwebserver httpport enableSplunkWebSSL privKeyPath caCertPath
syn keyword confPDFserver supportSSLV3Only root_endpoint static_endpoint static_dir enable_gzip
syn keyword confPDFserver server.thread_pool server.socket_host log.access_file log.error_file
syn keyword confPDFserver log.screen request.show_tracebacks engine.autoreload_on tools.sessions.on
syn keyword confPDFserver tools.sessions.timeout response.timeout tools.sessions.storage_type
syn keyword confPDFserver tools.sessions.storage_path tools.decode.on tools.encode.on tools.encode.encoding
syn keyword confPDFserver pid_path firefox_cmdline max_queue max_concurrent Xvfb xauth mcookie
syn keyword confPDFserver appserver_ipaddr client_ipaddr screenshot_enabled

" procmon-filters.conf
"syn keyword confProcmonFiltersStanzas
syn keyword confProcmonFilters proc type hive

" props.conf
syn match   confPropsStanzas contained /\v<(default|(rule|source|delayedrule|host)::[^\]]+)>/
syn keyword confProps host source sourcetype CHARSET TRUNCATE LINE_BREAKER LINE_BREAKER_LOOKBEHIND
syn keyword confProps SHOULD_LINEMERGE BREAK_ONLY_BEFORE_DATE BREAK_ONLY_BEFORE MUST_BREAK_AFTER
syn keyword confProps MUST_NOT_BREAK_AFTER MUST_NOT_BREAK_BEFORE MAX_EVENTS DATETIME_CONFIG TIME_PREFIX
syn keyword confProps MAX_TIMESTAMP_LOOKAHEAD TIME_FORMAT TZ MAX_DAYS_AGO MAX_DAYS_HENCE MAX_DIFF_SECS_AGO
syn keyword confProps MAX_DIFF_SECS_HENCE KV_MODE CHECK_FOR_HEADER
syn keyword confProps NO_BINARY_CHECK SEGMENTATION
syn keyword confProps CHECK_METHOD initCrcLength PREFIX_SOURCETYPE sourcetype rename invalid_cause is_valid
syn keyword confProps unarchive_cmd unarchive_sourcetype LEARN_SOURCETYPE LEARN_MODEL maxDist
syn keyword confProps ANNOTATE_PUNCT HEADER_MODE _actions pulldown_type
syn keyword confProps given_type TZ_ALIAS INDEXED_EXTRACTIONS PREAMBLE_REGEX FIELD_HEADER_REGEX HEADER_FIELD_LINE_NUMBER
syn keyword confProps FIELD_DELIMITER FIELD_QUOTE TIMESTAMP_FIELDS FIELD_NAMES detect_trailing_nulls
syn keyword confProps category HEADER_FIELD_DELIMITER HEADER_FIELD_QUOTE KV_TRIM_SPACES MISSING_VALUE_REGEX

syn match confComplex /\v<(EVAL|EXTRACT|FIELDALIAS|LOOKUP|REPORT|SEDCMD|SEGMENTATION|TRANSFORMS)-\k+>/
syn match confComplex /\v<(MORE|LESS)_THAN_\d+>/

" pubsub.conf
syn match   confPubsubStanzas contained /\v<(default|pubsub-server:[^\]]+)>/
syn keyword confPubsub disabled targetUri
syn keyword confPubsub_Constants direct

" regmon-filters.conf
syn match   confRegmonFiltersStanzas contained /\v<(default)>/
syn keyword confRegmonFilters proc hive type baseline baseline_interval disabled index

" restmap.conf
syn match   confRestmapStanzas contained /\v<(global|(script|admin|validation|eai|input|peerupload):[^\]]+)>/
syn keyword confRestmap allowGetAuth pythonHandlerPath match requireAuthentication capability
syn keyword confRestmap scripttype handler xsl script output_modes members handlertype handlerfile
syn keyword confRestmap handleractions showInDirSvc desc dynamic path untar
syn keyword confRestmap capability.post capability.delete capability.get capability.put
syn keyword confRestmap includeInAccessLog authKeyStanza 

syn match confComplex /\v<capability.(post|delete|get|put)>/

" savedsearches.conf
syn match   confSavedSearchesStanzas contained /\v<(default)>/
syn keyword confSavedSearches disabled search enableSched cron_schedule schedule max_concurrent
syn keyword confSavedSearches realtime_schedule counttype relation quantity alert_condition action.
syn keyword confSavedSearches action.email action.email.to action.email.from action.email.subject
syn keyword confSavedSearches action.email.subject action.email.mailserver action.populate_lookup
syn keyword confSavedSearches action.email.inline action.email.sendresults action.email.sendpdf
syn keyword confSavedSearches action.script action.summary_index action.script.filename
syn keyword confSavedSearches action.summary_index._name action.summary_index.inline action.summary_index.
syn keyword confSavedSearches action.summary_index.report_name action.summary_index.report
syn keyword confSavedSearches action.populate_lookup.dest run_on_startup dispatch.ttl dispatch.buckets
syn keyword confSavedSearches dispatch.max_count dispatch.max_time dispatch.lookups dispatch.earliest_time
syn keyword confSavedSearches dispatch.latest_time dispatch.time_format dispatch.spawn_process
syn keyword confSavedSearches dispatch.reduce_freq dispatch.rt_backfill restart_on_searchpeer_add
syn keyword confSavedSearches auto_summarize auto_summarize.command auto_summarize.timespan auto_summarize.hash
syn keyword confSavedSearches auto_summarize.cron_schedule auto_summarize.dispatch. auto_summarize.normalized_hash
syn keyword confSavedSearches auto_summarize.suspend_period auto_summarize.max_summary_size dispatchAs
syn keyword confSavedSearches auto_summarize.max_summary_ratio auto_summarize.max_disabled_buckets
syn keyword confSavedSearches auto_summarize.max_time alert.suppress alert.suppress.period dispatch.auto_cancel
syn keyword confSavedSearches alert.suppress.fields alert.severity alert.expires alert.digest_mode
syn keyword confSavedSearches alert.track displayview vsid is_visible description dispatch.auto_pause
syn keyword confSavedSearches request.ui_dispatch_app request.ui_dispatch_view sendresults action_rss
syn keyword confSavedSearches action_email role userid query nextrun qualifiedSearch dispatch.index_earliest
syn keyword confSavedSearches action.email.maxresults dispatch.indexedRealtime alert.display_view dispatch.index_latest
syn keyword confSavedSearches display.general.enablePreview display.general.type display.general.timeRangePicker.show display.general.migratedFromViewState
syn keyword confSavedSearches display.events.fields display.events.type display.events.rowNumbers display.events.maxLines display.events.raw.drilldown
syn keyword confSavedSearches display.events.list.drilldown display.events.list.wrap display.events.table.drilldown display.events.table.wrap
syn keyword confSavedSearches display.statistics.rowNumbers display.statistics.wrap display.statistics.overlay display.statistics.drilldown
syn keyword confSavedSearches display.visualizations.show display.visualizations.type display.visualizations.chartHeight
syn keyword confSavedSearches display.visualizations.charting.chart display.visualizations.charting.chart.stackMode
syn keyword confSavedSearches display.visualizations.charting.chart.nullValueMode display.visualizations.charting.drilldown
syn keyword confSavedSearches display.visualizations.charting.chart.style display.visualizations.charting.layout.splitSeries
syn keyword confSavedSearches display.visualizations.charting.legend.placement display.visualizations.charting.legend.labelStyle.overflowMode
syn keyword confSavedSearches display.visualizations.charting.axisTitleX.text display.visualizations.charting.axisTitleY.text
syn keyword confSavedSearches display.visualizations.charting.axisTitleX.visibility display.visualizations.charting.axisTitleY.visibility
syn keyword confSavedSearches display.visualizations.charting.axisX.scale display.visualizations.charting.axisY.scale
syn keyword confSavedSearches display.visualizations.charting.axisLabelsX.majorUnit display.visualizations.charting.axisLabelsY.majorUnit
syn keyword confSavedSearches display.visualizations.charting.axisX.minimumNumber display.visualizations.charting.axisY.minimumNumber
syn keyword confSavedSearches display.visualizations.charting.axisX.maximumNumber display.visualizations.charting.axisY.maximumNumber
syn keyword confSavedSearches display.visualizations.charting.chart.sliceCollapsingThreshold display.visualizations.charting.gaugeColors
syn keyword confSavedSearches display.visualizations.charting.chart.rangeValues display.visualizations.singlevalue.beforeLabel
syn keyword confSavedSearches display.visualizations.singlevalue.afterLabel display.visualizations.singlevalue.underLabel
syn keyword confSavedSearches display.page.search.mode display.page.search.timeline.format display.page.search.timeline.scale
syn keyword confSavedSearches display.page.search.showFields display.page.pivot.dataModel
syn keyword confSavedSearches display.page.search.patterns.sensitivity display.page.search.tab display.visualizations.charting.axisLabelsX.majorLabelStyle.overflowMode
syn keyword confSavedSearches display.visualizations.charting.axisLabelsX.majorLabelStyle.rotation display.visualizations.charting.axisLabelsY2.majorUnit
syn keyword confSavedSearches display.visualizations.charting.axisTitleY2.text display.visualizations.charting.axisTitleY2.visibility
syn keyword confSavedSearches display.visualizations.charting.axisY2.enabled display.visualizations.charting.axisY2.maximumNumber
syn keyword confSavedSearches display.visualizations.charting.axisY2.minimumNumber display.visualizations.charting.axisY2.scale
syn keyword confSavedSearches display.visualizations.charting.chart.bubbleMaximumSize display.visualizations.charting.chart.bubbleMinimumSize display.visualizations.charting.chart.bubbleSizeBy
syn keyword confSavedSearches display.visualizations.charting.chart.overlayFields
syn keyword confSavedSearches display.visualizations.mapHeight display.visualizations.mapping.data.maxClusters display.visualizations.mapping.drilldown display.visualizations.mapping.map.center display.visualizations.mapping.map.zoom display.visualizations.mapping.markerLayer.markerMaxSize display.visualizations.mapping.markerLayer.markerMinSize display.visualizations.mapping.markerLayer.markerOpacity
syn keyword confSavedSearches display.visualizations.mapping.tileLayer.maxZoom display.visualizations.mapping.tileLayer.minZoom display.visualizations.mapping.tileLayer.url
syn keyword confSavedSearches_Constants fast smart verbose hidden compact full linear log events statistics visualizations
syn keyword confSavedSearches_Constants heatmap highlow stacked default stacked100 right bottom top left visible collapsed
syn keyword confSavedSearches_Constants mapping embed.enabled diameter bubble gaps zero connect ellipsisNone user owner
syn keyword confSavedSearches_Constants patterns all

" searchbnf.conf
syn match   confSearchbnfStanzas contained /\v<(default|[^-]+-(command|options))>/
syn case ignore
syn keyword confSearchbnf syntax simplesyntax alias description shortdesc example comment usage tags
syn keyword confSearchbnf related maintainer appears-in note supports-multivalue
syn case match

" segmenters.conf
syn match   confSegmentersStanzas contained /\v<(default)>/
syn keyword confSegmenters MAJOR MINOR INTERMEDIATE_MAJORS FILTER LOOKAHEAD MAJOR_LEN MINOR_LEN
syn keyword confSegmenters MAJOR_COUNT MINOR_COUNT

" server.conf
syn match   confServerStanzas contained /\v<(applicationsManagement|cluster(ing|master:[^\]]+)|default|diag|diskUsage|fileInput)>/
syn match   confServerStanzas contained /\v<(general|httpServer(Listener:[^\]]+)?| license)>/
syn match   confServerStanzas contained /\v<(lmpool:auto_generated_pool_(download_trial|enterprise|forwarder|free|fixed-sourcetype_[^\]]+))>/
syn match   confServerStanzas contained /\v<(mimetype-extension-map|pooling|pubsubsvr-http|queue(\=[^\]]+)?)>/
syn match   confServerStanzas contained /\v<(replication_port(-ssl)?|scripts|sslConfig)>/
syn keyword confServer serverName sessionTimeout trustedIP allowRemoteLogin pass4SymmKey listenOnIPv6
syn keyword confServer connectUsingIpVersion guid useHTTPServerCompression useHTTPClientCompression
syn keyword confServer enableSplunkdSSL useSplunkdClientSSLCompression supportSSLV3Only sslVerifyServerCert
syn keyword confServer sslCommonNameToCheck sslAltNameToCheck requireClientCert cipherSuite sslKeysfile
syn keyword confServer sslKeysfilePassword caCertFile caPath certCreateScript atomFeedStylesheet
syn keyword confServer max-age follow-symlinks disableDefaultPort acceptFrom streamInWriteTimeout
syn keyword confServer max_content_length ssl allowInternetAccess url loginUrl detailsUrl useragent
syn keyword confServer updateHost updatePath updateTimeout initialNumberOfScriptProcesses minFreeSpace
syn keyword confServer pollingFrequency pollingTimerFrequency maxSize disabled stateIntervalInSecs
syn keyword confServer outputQueue master_uri active_group connection_timeout send_timeout
syn keyword confServer receive_timeout squash_threshold description quota slaves stack_id state storage
syn keyword confServer lock.timeout lock.logging poll.interval.rebuild poll.interval.check poll.blacklist.
syn keyword confServer mode cxn_timeout rcv_timeout rep_cxn_timeout rep_send_timeout rep_rcv_timeout
syn keyword confServer rep_max_send_timeout rep_max_rcv_timeout replication_factor search_factor
syn keyword confServer heartbeat_timeout restart_timeout quiet_period generation_poll_interval
syn keyword confServer max_peer_build_load max_peer_rep_load searchable_targets register_replication_address
syn keyword confServer register_forwarder_address register_search_address heartbeat_period
syn keyword confServer defaultHTTPServerCompressionLevel skipHTTPCompressAcl sslCommonNameList sendStrictTransportSecurityHeader
syn keyword confServer allowSslCompression allowSslRenegotiation maxThreads maxSockets forceHttp10 crossOriginSharingPolicy
syn keyword confServer x_fram_options_sameorigin cliLoginBanner allowBasicAuth basicAuthRealm cntr_1_lookback_time
syn keyword confServer cntr_2_lookback_time cntr_3_lookback_time sampling_interval app_update_triggers search_files_retry_timeout
syn keyword confServer max_replication_errors target_wait_time commit_retry_time percent_peers_to_restart executor_workers
syn keyword confServer access_logging_for_heartbeats access_logging_for_phonehome acquireExtra_i_data adhoc_searchhead
syn keyword confServer alert_proxying all_dumps allowCookieAuth allowEmbedTokenAuth async_replicate_on_proxy 
syn keyword confServer auto_rebalance_primaries available_sites captain_is_adhoc_searchhead collectionPeriodInSecs
syn keyword confServer collectionStatsCollectionPeriodInSecs components conf_deploy_concerning_file_size
syn keyword confServer conf_deploy_fetch_mode conf_deploy_fetch_url conf_deploy_repository conf_deploy_staging
syn keyword confServer conf_replication_include. conf_replication_max_pull_count conf_replication_max_push_count
syn keyword confServer conf_replication_period conf_replication_purge.eligibile_age conf_replication_purge.eligibile_count
syn keyword confServer conf_replication_purge.period conf_replication_summary.blacklist. conf_replication_summary.concerning_file_size
syn keyword confServer conf_replication_summary.period conf_replication_summary.whitelist. cookieAuthHttpOnly
syn keyword confServer cookieAuthSecure cxn_timeout_raft dbPath distributedLookupTimeout election_timeout_2_hb_ratio
syn keyword confServer election_timeout_ms embedSecret etc_filesize_limit hangup_after_phonehome
syn keyword confServer hostnameOption idle_connections_pool_size index_files index_listing initAttempts instanceType
syn keyword confServer log_age log_heartbeat_append_entries long_running_jobs_poll_period master_dump_service_periods
syn keyword confServer mgmt_uri multisite oplogSize pool_suggestion prefix profilingStatsCollectionPeriodInSecs
syn keyword confServer ra_proxying rcv_timeout_raft replicaset replication_host replicationWriteTimeout report_interval
syn keyword confServer rsStatsCollectionPeriodInSecs scheduling_heuristic searchable_target_sync_timeout send_timeout_raft
syn keyword confServer servers_list serverStatsCollectionPeriodInSecs service_interval service_jobs_msec shutdownTimeout
syn keyword confServer sid_proxying site_replication_factor site_search_factor site skipHTTPCompressionAcl ss_proxying
syn keyword confServer strict_pool_quota use_batch_mask_changes verbose
syn keyword confServer_Constants always never requireSetPassword KB MB GB self Enterprise Trial Forwarder Free
syn keyword confServer_Constants master slave searchhead enabled clustermaster: silence silent replace on-http on-https
syn keyword confServer_Constants 4-first 6-first 4-only 6-only MAX

syn match confComplex /\v<EXCLUDE-\k+/

" serverclass.conf
syn match   confServerClassStanzas contained /\v<(global|serverClass:[^\]]+)>/
syn keyword confServerClass repositoryLocation targetRepositoryLocation tmpFolder continueMatching
syn keyword confServerClass endpoint filterType machineTypes machineTypesFilter whitelist. blacklist.
syn keyword confServerClass restartSplunkWeb restartSplunkd stateOnClient appFile excludeFromUpdate

syn match   confComplex /\v<(white|black)list\.\d+>/

" source-classifier.conf
"syn keyword confSourceClassStanzas
syn keyword confSourceClass ignored_model_keywords ignored_filename_keywords

" sourcetypes.conf
syn match   confSourceTypesStanzas contained /\v<(default)>/
syn keyword confSourceTypes _sourcetype _source

" splunk-launch.conf
"syn keyword confSplunkLaunchStanzas
syn keyword confSplunkLaunch SPLUNK_HOME SPLUNK_DB SPLUNK_BINDIP SPLUNK_IGNORE_SELINUX SPLUNK_SERVER_NAME
syn keyword confSplunkLaunch SPLUNK_WEB_NAME SPLUNK_OS_USER

"" tags.conf
"syn keyword confTagsStanzas
"syn keyword confTags

" tenants.conf
syn match   confTenantsStanzas contained /\v<(default|tenant:[^\]]+)>/
syn keyword confTenants filterType whitelist. blacklist. phoneHomeTopic

" times.conf
syn match   confTimesStanzas contained /\v<(default)>/
syn keyword confTimes label header_label earliest_time latest_time order sub_menu is_sub_menu

" transactiontypes.conf
syn match   confTransactionTypesStanzas contained /\v<(default)>/
syn keyword confTransactionTypes maxspan maxpause maxevents fields startswith endswith connected maxopentxn
syn keyword confTransactionTypes maxopenevents keepevicted mvlist delim nullstr search

" transforms.conf
syn match   confTransformsStanzas contained /\v<(default|accepted_keys)>/
syn keyword confTransforms REGEX FORMAT LOOKAHEAD WRITE_META DEST_KEY DEFAULT_VALUE SOURCE_KEY
syn keyword confTransforms REPEAT_MATCH DELIMS FIELDS MV_ADD CLEAN_KEYS KEEP_EMPTY_VALS CAN_OPTIMIZE
syn keyword confTransforms filename max_matches min_matches default_match case_sensitive_match
syn keyword confTransforms match_type external_cmd fields_list external_type time_field time_format
syn keyword confTransforms max_offset_secs min_offset_secs batch_index_query allow_caching
syn keyword confTransforms CLONE_SOURCETYPE collection max_ext_batch
syn keyword confTransforms_Constants _raw _done _meta _time MetaData:FinalType MetaData:Host queue
syn keyword confTransforms_Constants _MetaData:Index MetaData:Source MetaData:Sourcetype

syn match confComplex /\v<(KEY\k+)>/

" ui-prefs.conf
syn match   confUIPrefsStanzas contained /\v<(default)>/
syn keyword confUIPrefs dispatch.earliest_time dispatch.latest_time display.prefs.autoOpenSearchAssistant display.prefs.timeline.height
syn keyword confUIPrefs display.prefs.timeline.minimized display.prefs.timeline.minimalMode display.prefs.aclFilter display.prefs.searchContext
syn keyword confUIPrefs display.prefs.events.count display.prefs.statistics.count display.prefs.fieldCoverage display.general.enablePreview
syn keyword confUIPrefs display.events.fields display.events.type display.events.rowNumbers display.events.maxLines display.events.raw.drilldown
syn keyword confUIPrefs display.events.list.drilldown display.events.list.wrap display.events.table.drilldown display.events.table.wrap
syn keyword confUIPrefs display.statistics.rowNumbers display.statistics.wrap display.statistics.drilldown display.visualizations.type
syn keyword confUIPrefs display.visualizations.chartHeight display.visualizations.charting.chart display.visualizations.charting.chart.style
syn keyword confUIPrefs display.visualizations.charting.legend.labelStyle.overflowMode display.page.search.mode display.page.search.timeline.format
syn keyword confUIPrefs display.page.search.timeline.scale display.page.search.showFields display.page.home.showGettingStarted
syn keyword confUIPrefs display.prefs.enableMetaData display.prefs.listMode display.prefs.showDataSummary
syn keyword confUIPrefs_Constants none app owner raw list table inner outer full row cell charting singlevalue line area column bar pie scatter
syn keyword confUIPrefs_Constants radialGauge fillerGauge markerGauge minimal shiny ellipsisEnd ellipsisMiddle ellipsisStart fast smart verbose
syn keyword confUIPrefs_Constants hidden compact full linear log tiles

" user-prefs.conf
syn match   confUserPrefsStanzas contained /\v<(general|default)>/
syn keyword confUserPrefs default_namespace tz

" user-seed.conf
syn match   confUserSeedStanzas contained /\v<(user_info)>/
syn keyword confUserSeed USERNAME PASSWORD

" viewstates.conf
syn match   confViewStatesStanzas contained /\v<(default)>/
"syn keyword confViewStates

" web.conf
syn match   confWebStanzas contained /\v<(settings|endpoint:[^\]]+)>/
syn keyword confWeb startwebserver httpport mgmtHostPort enableSplunkWebSSL privKeyPath caCertPath
syn keyword confWeb serviceFormPostURL userRegistrationURL updateCheckerBaseURL docsCheckerBaseURL
syn keyword confWeb enable_insecure_login login_content supportSSLV3Only cipherSuite root_endpoint
syn keyword confWeb static_endpoint static_dir rss_endpoint tools.staticdir.generate_indexes
syn keyword confWeb template_dir module_dir enable_gzip use_future_expires flash_major_version
syn keyword confWeb flash_minor_version flash_revision_version enable_proxy_write js_logger_mode
syn keyword confWeb js_logger_mode_server_end_point js_logger_mode_server_poll_buffer
syn keyword confWeb js_logger_mode_server_max_buffer ui_inactivity_timeout js_no_cache
syn keyword confWeb enable_autocomplete_login minify_js minify_css trap_module_exceptions
syn keyword confWeb jschart_test_mode max_view_cache_size version_label_format remoteUser SSOMode
syn keyword confWeb trustedIP testing_endpoint testing_dir server.thread_pool server.thread_pool_max
syn keyword confWeb server.thread_pool_min_spare server.thread_pool_max_spare server.socket_host
syn keyword confWeb listenOnIPv6 max_upload_size log.access_maxsize log.access_maxfiles
syn keyword confWeb log.error_maxsize log.error_maxfiles log.screen request.show_tracebacks
syn keyword confWeb engine.autoreload_on tools.session.on tools.sessions.timeout
syn keyword confWeb tools.sessions.restart_persist tools.sessions.httponly tools.sessions.secure
syn keyword confWeb response.timeout tools.sessions.storage_type tools.sessions.storage_path
syn keyword confWeb tools.decode.on tools.encode.on tools.encode.encoding tools.proxy.on pid_path
syn keyword confWeb enabled_decomposers trustedIP remoteUser SSOMode
syn keyword confWeb splunkConnectionTimeout simple_xml_force_flash_charting pdfgen_is_available auto_refresh_views
syn keyword confWeb x_frame_options_sameorigin simple_xml_module_render simple_xml_perf_debug django_enable
syn keyword confWeb django_path django_force_enable
syn keyword confWeb appServerPorts splunkdConnectionTimeout sslVersions remoteUserMatchExact allowSsoWithoutChangingServerConf
syn keyword confWeb embed_uri embed_footer cacheBytesLimit cacheEntriesLimit staticCompressionLevel verifyCookiesWorkDuringLogin
syn keyword confWeb enable_pivot_adhoc_acceleration pivot_adhoc_acceleration_mode jschart_trunctation_limit
syn keyword confWeb jschart_truncation_limit.chrome jschart_truncation_limit.firefox jschart_truncation_limit.safari
syn keyword confWeb jschart_truncation_limit.ie11 jschart_truncation_limit.ie10 jschart_truncation_limit.ie9
syn keyword confWeb jschart_truncation_limit.ie8 jschart_truncation_limit.ie7 server.socket_timeout
syn keyword confWeb override_JSON_MIME_type_with_text_plain job_min_polling_interval job_max_polling_interval
syn keyword confWeb dedicatedIoThreads methods pattern skipCSRFProtection oidEnabled export_timeout
syn keyword confWeb tools.proxy.base
syn keyword confWeb_Constants None Firebug Server permissive strict no yes only

" wmi.conf
syn match   confWmiStanzas contained /\v<(settings|WMI:[^\]]+)>/
syn keyword confWmi initial_backoff max_backoff max_retries_at_max_backoff checkpoint_sync_interval
syn keyword confWmi server interval disabled hostname current_only index event_log_file
syn keyword confWmi disable_hostname_normalization wql namespace

" workflow_actions.conf
syn match   confWorkflowActionsStanzas contained /\v<(default)>/
syn keyword confWorkflowActions type label fields eventtypes display_location disabled link.uri
syn keyword confWorkflowActions link.target link.method link.postargs. search.search_string search.app
syn keyword confWorkflowActions search.view search.target search.earliest search.latest
syn keyword confWorkflowActions search.preserve_timerange


" Highlight definitions (generic)
hi def link confComment Comment
hi def link confSpecComment Comment
hi def link confBoolean Boolean
hi def link confTodo Todo

hi def link confStanzaStart Delimiter
hi def link confstanzaEnd Delimiter

" Highlight for stanzas
hi def link confStanza Function
hi def link confGenericStanzas Function
hi def link confAlertActionsStanzas Identifier
hi def link confAppStanzas Identifier
hi def link confAuditStanzas Identifier
hi def link confAuthenticationStanzas Identifier
hi def link confAuthorizeStanzas Identifier
hi def link confCollectionsStanzas Identifier
hi def link confCommandsStanzas Identifier
hi def link confCrawlStanzas Identifier
hi def link confDataModelsStanzas Identifier
hi def link confDataTypesbnfStanzas Identifier
hi def link confDefmodeStanzas Identifier
hi def link confDeployClientStanzas Identifier
hi def link confDistSearchStanzas Identifier
hi def link confEventDiscoverStanzas Identifier
hi def link confEventGenStanzas Identifier
hi def link confEventRenderStanzas Identifier
hi def link confEventTypesStanzas Identifier
hi def link confFieldsStanzas Identifier
hi def link confIndexesStanzas Identifier
hi def link confInputsStanzas Identifier
hi def link confLimitsStanzas Identifier
hi def link confMetaStanzas Identifier
hi def link confOutputsStanzas Identifier
hi def link confPDFserverStanzas Identifier
hi def link confPropsStanzas Identifier
hi def link confPubsubStanzas Identifier
hi def link confRegmonFiltersStanzas Identifier
hi def link confRestmapStanzas Identifier
hi def link confSavedSearchesStanzas Identifier
hi def link confSegmenterStanzas Identifier
hi def link confServerClassStanzas Identifier
hi def link confServerStanzas Identifier
hi def link confSourceTypesStanzas Identifier
hi def link confTenantsStanzas Identifier
hi def link confTimesStanzas Identifier
hi def link confTransactionTypesStanzas Identifier
hi def link confTransformsStanzas Identifier
hi def link confUIPrefsStanzas Identifier
hi def link confUserPrefsStanzas Identifier
hi def link confUserSeedStanzas Identifier
hi def link confViewStatesStanzas Identifier
hi def link confWebStanzas Identifier
hi def link confWmiStanzas Identifier
hi def link confWorkflowActionsStanzas Identifier
hi def link confSearchbnfStanzas Identifier

" Other highlights
hi def link confString String
hi def link confNumber Number
hi def link confPath   Number
hi def link confVar    PreProc

" Highlight definitions (by .conf)
hi def link confADmon Keyword
hi def link confAlertActions Keyword
hi def link confApp Keyword
hi def link confAudit Keyword
hi def link confAuthentication Keyword
hi def link confAuthorize Keyword
hi def link confCollections Keyword
hi def link confCommands Keyword
hi def link confCrawl Keyword
hi def link confDataTypesbnf Keyword
hi def link confDataModels Keyword
hi def link confDefmode Keyword
hi def link confDeployClient Keyword
hi def link confDistSearch Keyword
hi def link confEventRender Keyword
hi def link confEventDiscover Keyword
hi def link confEventGen Keyword
hi def link confEventTypes Keyword
hi def link confFields Keyword
hi def link confIndexes Keyword
hi def link confIndexes_Constants Constant
hi def link confInputs Keyword
hi def link confLimits Keyword
hi def link confMeta Keyword
hi def link confMeta_Constants Constant
hi def link confMacros Keyword
hi def link confMultikv Keyword
hi def link confOutputs Keyword
hi def link confPDFserver Keyword
hi def link confProcmonFilters Keyword
hi def link confProps Keyword
hi def link confComplex Preproc
hi def link confPubsub Keyword
hi def link confPubsub_Constants Constant
hi def link confRegmonFilters Keyword
hi def link confRestmap Keyword
hi def link confSavedSearches Keyword
hi def link confSavedSearches_Constants Constant
hi def link confSearchbnf Keyword
hi def link confSegmenters Keyword
hi def link confServer Keyword
hi def link confServer_Constants Constant
hi def link confServerClass Keyword
hi def link confSourceClass Keyword
hi def link confSourceTypes Keyword
hi def link confSplunkLaunch Keyword
hi def link confTags Keyword
hi def link confTenants Keyword
hi def link confTimes Keyword
hi def link confTransactionTypes Keyword
hi def link confTransforms Keyword
hi def link confTransforms_Constants Constant
hi def link confUIPrefs Keyword
hi def link confUIPrefs_Constants Constant
hi def link confUserPrefs Keyword
hi def link confUserSeed Keyword
hi def link confViewStates Keyword
hi def link confWeb Keyword
hi def link confWeb_Constants Constant
hi def link confWmi Keyword
hi def link confWorkflowActions Keyword
