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
syn match confSpecComment /^\s*\*.*/ contains=confTodo oneline display

syn region confString start=/"/ skip="\\\"" end=/"/ oneline display contains=confNumber,confVar
syn region confString start=/`/             end=/`/ oneline display contains=confNumber,confVar
syn region confString start=/'/ skip="\\'"  end=/'/ oneline display contains=confNumber,confVar
syn match  confNumber /\v[+-]?\d+([ywdhsm]|m(on|ins?))(\@([ywdhs]|m(on|ins?))\d*)?>/
syn match  confNumber /\v[+-]?\d+(\.\d+)*>/
syn match  confNumber /\v<\d+[TGMK]B>/
syn match  confPath   ,\v(^|\s|\=)\zs(file:|https?:|\$\k+)?(/+\k+)+(:\d+)?,
syn match  confPath   ,\v(^|\s|\=)\zsvolume:\k+(/+\k+)+,
syn match  confVar    /\$\k\+\$/

syn keyword confBoolean on off t[rue] f[alse] T[rue] F[alse]
syn keyword confTodo FIXME NOTE TODO contained

" Define stanzas
syn region confStanza matchgroup=confStanzaStart start=/^\[/ matchgroup=confStanzaEnd end=/\]/ oneline transparent contains=@confStanzas

" Group clusters
syn cluster confStanzas contains=confAlertActionsStanzas,confAppStanzas,confAuditStanzas,confAuthenticationStanzas,confAuthorizeStanzas,confChecklistStanzas,confCommandsStanzas,confCrawlStanzas,confDataModelsStanzas,confDefmodeStanzas,confDeployClientStanzas,confDistSearchStanzas,confDMCAlertsStanzas,confEventGenStanzas,confEventRenderStanzas,confEventDiscoverStanzas,confEventTypesStanzas,confFieldsStanzas,confIndexesStanzas,confInputsStanzas,confLauncherStanzas,confSALDAPStanzas,confSALDAPLoggingStanzas,confSALDAPSSLStanzas,confLimitsStanzas,confLivetailStanzas,confOutputsStanzas,confPDFserverStanzas,confPropsStanzas,confPubsubStanzas,confRegmonFiltersStanzas,confRestmapStanzas,confSavedSearchesStanzas,confSegmenterStanzas,confServerStanzas,confServerClassStanzas,confSourceTypesStanzas,confMCAssetsStanzas,confTenantsStanzas,confTimesStanzas,confTransactionTypesStanzas,confTransformsStanzas,confUIPrefsStanzas,confUITourStanzas,confUserSeedStanzas,confViewStatesStanzas,confWebStanzas,confWmiStanzas,confWorkflowActionsStanzas,confGenericStanzas,confMetaStanzas,confSearchbnfStanzas,confCollectionsStanzas,confDataTypesbnfStanzas,confUserPrefsStanzas,confInstanceStanzas

syn match confGenericStanzas display contained /\v[^\]]+/

" admon.conf
syn keyword confADmon targetDc startingNode monitorSubtree disabled index

" alert_actions.conf
syn match   confAlertActionsStanzas contained /\v<(default|email|rss|script|summary_index|populate_lookup)>/
syn keyword confAlertActions maxresults hostname ttl maxtime track_alert command
syn keyword confAlertActions from to cc bcc subject format sendresults inline
syn keyword confAlertActions sendpdf pdfview useNSSubject mailserver
syn keyword confAlertActions width_sort_columns preprocess_results items_count filename _name dest
syn keyword confAlertActions sendcsv priority inline is_custom payload_format icon_path content_type icon_path
syn match   confAlertActions /\v<use_(ssl|tls)|auth_(username|password)>/
syn match   confAlertActions /\v<report(Paper(Size|Orientation)|Server(Enabled|URL)|IncludeSplunkLogo|CIDFontList|FileName)>/
syn match   confAlertActions /\v<pdf\.(logo_path|html_image_rendering|(footer|header)_(enabled|center|left|right))>/
syn match   confAlertActions /\v<alert\.execute\.cmd(\.arg\.\S+)?>/
syn match   confAlertActions /\v<subject\.(alert|report)|message\.(report|alert)|footer\.text|include\.((results|view)_link|search|trigger|trigger_time)>/

syn keyword confAlertActions_Constants logo title description timestamp pagination none csv html plain
syn keyword confAlertActions_Constants letter legal ledger a2 a3 a4 a5 portrait landscape

" alert_logevent
" alert_actions.conf

syn match   confAlertActions /\v<param\.(event|host|source(type)?|index)>/

" app.conf
syn match   confAppStanzas contained /\v<(launcher|package|install|triggers|ui|credentials_settings|credential:[^\]]+)>/
syn keyword confApp remote_tab version description author id check_for_updates docs_section_override
syn keyword confApp state state_change_requires_restart is_configured build allows_disable
syn keyword confApp is_visible is_manageable label verify_script password default_gather_lookups
syn keyword confApp install_source_checksum docs_section_override show_in_nav
syn keyword confApp attribution_link data_limit extension_script setup_view
syn match   confApp /\v<reload\.\S+>/

syn keyword confApp_Constants simple rest_endpoints access_endpoints http_get http_post

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
syn keyword confAuthentication minPasswordLength fqdn redirectPort idpSSOUrl idpAttributeQueryUrl
syn keyword confAuthentication idpCertPath idpSLOUrl entityId signAuthnRequest signedAssertion
syn keyword confAuthentication attributeQuerySoapPassword attributeQuerySoapUsername signatureAlgorithm
syn keyword confAuthentication attributeQueryRequestSigned attributeQueryResponseSigned
syn keyword confAuthentication redirectAfterLogoutToUrl defaultRoleIfMissing clientCert
syn keyword confAuthentication skipAttributeQueryRequestForUsers maxAttributeQueryThreads
syn keyword confAuthentication maxAttributeQueryQueueSize attributeQueryTTL nameIdFormat role mail realName blacklistedAutoMappedRoles blacklistedUsers
syn keyword confAuthentication apiHostname failOpen
syn match   confAuthentication /\v<(appSecret|integration|secret)Key>/
syn match   confAuthentication /\v<ecdhCurve(s|Name)|errorUrl(Label)?>/
syn match   confAuthentication /\v<externalTwoFactorAuth(Settings|Vendor)>/
syn match   confAuthentication /\v<(sso|slo)Binding>/

syn keyword confAuthentication_Constants Splunk LDAP Scripted SAML
syn match   confAuthentication_Constants /\v<SHA(256|512)-crypt(-\d+)?|MD5-crypt|RSA-SHA\d+>/

" authorize.conf
syn match   confAuthorizeStanzas contained /\v<(default|(capability::|role_)[^\]]+)>/
syn keyword confAuthorize importRoles grantableRoles srchFilter srchTimeWin srchDiskQuota srchJobsQuota
syn keyword confAuthorize rtSrchJobsQuota srchMaxTime srchIndexesDefault srchIndexesAllowed
syn keyword confAuthorize cumulativeSrchJobsQuota cumulativeRTSrchJobsQuota rtsearch schedule_rtsearch
syn keyword confAuthorize srchFilterSelecting deleteIndexesAllowed
" capabilities
syn keyword confAuthorizeCaps admin_all_objects delete_by_keyword input_file indexes_edit license_tab output_file request_remote_tok
syn keyword confAuthorizeCaps restart_splunkd rtsearch run_debug_commands schedule_search schedule_rtsearch search use_file_operator
syn keyword confAuthorizeCaps web_debug
syn match   confAuthorizeCaps /\v<accelerate_(search|datamodel)>/
syn match   confAuthorizeCaps /\v<change_(authentication|own_password)>/
syn match   confAuthorizeCaps /\v<edit_(deployment_(client|server)|dist_peer|forwarders|httpauths|input_defaults|monitor|roles)>/
syn match   confAuthorizeCaps /\v<edit_(scripted|search|search_(head_clustering|scheduler|server)|server|sourcetypes|splunktcp(_ssl)?)>/
syn match   confAuthorizeCaps /\v<edit_(tcp|udp|token_http|user|view_html|web_settings)>/
syn match   confAuthorizeCaps /\v<list_(deployment_(client|server)|search_scheduler|forwarders|httpauths|inputs|search_head_clustering)>/
syn match   confAuthorizeCaps /\v<get_(diag|metadata|typeahead)>/
syn match   confAuthorizeCaps /\v<rest_(apps_(management|view)|properties_(g|s)et)>/

" splunk_monitoring_console
" checklist.conf
syn match   confChecklistStanzas contained /\v[^\]]+/
syn keyword confChecklist title category tags description failure_text suggested_action doc_link applicable_to_groups
syn keyword confChecklist environments_to_exclude disabled search drilldown

" collections.conf
syn match   confCollectionsStanzas contained /\v[^\]]+/
syn keyword confCollections enforceTypes profilingEnabled profilingThresholdMs
syn keyword confCollections replicate replication_dump_strategy replication_dump_maximum_file_size
syn match   confCollections /\v<field\.\S+|accelerated_fields\.\S+>/

syn keyword confCollections_Constants one_file auto internal_cache undefined

" commands.conf
syn match   confCommandsStanzas contained /\v<(default)>/
"syntax case ignore
syn keyword confCommands type filename local perf_warn_limit streaming maxinputs passauth
syn keyword confCommands run_in_preview enableheader retainsevents generating generates_timeorder
syn keyword confCommands overrides_timeorder requires_preop streaming_preop required_fields
syn keyword confCommands undo_scheduler_escaping
syn keyword confCommands requires_srinfo needs_empty_results changes_colorder clear_required_fields
syn keyword confCommands stderr_dest outputheader chunked maxwait maxchunksize
syn match   confCommands /\v<supports_(multivalues|getinfo|rawargs)>/
syn match   confCommands /\v<command\.\w+\.\d+>/
syn match   confCommands /\v<is_(order_sensitive|risky)>/
"syntax case match

syn keyword confCommands_Constants log message none

" crawl.conf
syn match   confCrawlStanzas contained /\v<(default|files|network)>/
syn keyword confCrawl collapse_threshold big_dir_filecount index max_badfiles_per_dir
syn keyword confCrawl host subnet root
syn match   confCrawl /\v<bad_(directories|extensions|file_matches)_list>/
syn match   confCrawl /\v<(packed_extensions|days_sizek_pairs)_list>/

" datamodels.conf
syn match   confDataModelsStanzas contained /\v<(default)>/
syn keyword confDataModels acceleration 
syn match   confDataModels /\v<acceleration\.((earliest|backfill|max)_time|cron_schedule|manual_rebuilds|max_concurrent|schedule_priority)>/
syn match   confDataModels /\v<acceleration\.hunk\.(compression_codec|dfs_block_size|file_format)>/
syn match   confDataModels /\v<dataset\.(description|type|commands|fields|display\.(diversity|sample_ratio|limiting|currentCommand|mode|datasummary\.((earliest|latest)Time)))>/

syn keyword confDataModelsConstants default higher highest datasummary table

" datatypesbnf.conf
syn match   confDataTypesbnfStanzas contained /\v[^\]]+/
syn keyword confDataTypesbnf syntax

" default-mode.conf
syn match   confDefModeStanzas contained /\v<(pipeline:[^\]]+)>/
syn keyword confDefMode disabled disabled_processors

" deployment.conf
" placeholder, file not used

" deploymentclient.conf
syn match   confDeployClientStanzas contained /\v<(default|deployment-client|target-broker:deploymentServer)>/
syn keyword confDeployClient disabled clientName workingDir repositoryLocation
syn keyword confDeployClient reloadDSOnAppInstall targetUri endpoint
syn match   confDeployClient /\v<(phoneHome|appEventsResync)IntervalInSecs>/
syn match   confDeployClient /\v<handshake(ReplySubscriptionRetry|RetryIntervalInSecs)>/
syn match   confDeployClient /\v<(server(RepositoryLocation|Endpoint)Policy)>/

syn keyword confDeployClient_Constants acceptSplunkHome acceptAlways rejectAlways

" distsearch.conf
syn match   confDistSearchStanzas contained /\v<(default|distributedSearch(:[^\]]+)?|tokenExchKeys|searchhead:[^\]]+)>/
syn match   confDistSearchStanzas contained /\v<replication(Settings(:refineConf)?|(White|Black)list)>/
syn match   confDistSearchStanzas contained /\v<bundleEnforcer(White|Black)list>/
syn keyword confDistSearch disabled ttl shareBundles useSHPBundleReplication
syn keyword confDistSearch autoAddServers bestEffortSearch skipOurselves servers disabled_servers
syn keyword confDistSearch certDir publicKey privateKey genKeyScript quarantined_servers
syn keyword confDistSearch replicationThreads maxMemoryBundleSize defaultUriScheme
syn keyword confDistSearch maxBundleSize concerningReplicatedFileSize
syn keyword confDistSearch mounted_bundles bundles_location trySSLFirst peerResolutionThreads
syn keyword confDistSearch servers default allConf sanitizeMetaFiles excludeReplicatedLookupSize
syn match   confDistSearch /\v<allow(SkipEncoding|(Delta|Stream)Upload)>/
syn match   confDistSearch /\v<(sendRcv|server|connection|status|authToken(Send|Receive|Connection))Timeout|(removed|check)TimedOutServers(Frequency)?>/
syn match   confDistSearch /\v<heartbeat(McastAddr|Port|Frequency)>/
syn match   confDistSearch /\v<replicate\.\S+>/
syn match   confDistSearch /\v<(receive|send)Timeout>/

" splunk_monitoring_console
" dmc_alerts.conf

syn match   confDMCAlertsStanzas contained /\v[^\]]+/
syn keyword confDMCAlerts param_to_search_conversion description_template search_template is_editable
syn match   confDMCAlerts /\v<parameter_(labels|values|ranges)>/
syn match   confDMCAlerts /\v<enabled_for_(cloud|light)>/

" eventdiscoverer.conf
syn match   confEventDiscoverStanzas contained /\v<(default)>/
syn keyword confEventDiscover important_keywords
syn match   confEventDiscover /\v<ignored_(keywords|fields)>/

" event_renderers.conf
syn match   confEventRenderStanzas contained /\v<(default)>/
syn keyword confEventRender eventtype priority template css_class

" eventgen.conf
syn match   confEventGenStanzas contained /\v<(default|global)>/
syn keyword confEventGen spoolDir spoolFile interval count earliest latest breaker token 
syn keyword confEventGen replacement replacementType outputMode maxIntervalsBeforeFlush
syn match   confEventGen /\v<token\.\d+\.(token|replacement(Type)?)>/
syn match   confEventGen /\v<splunk(Host|User|Pass)>/

" eventtypes.conf
syn match   confEventTypesStanzas contained /\v<(default>|\k+-\%\k+\%)/
syn keyword confEventTypes disabled search priority description tags color

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
syn keyword confIndexes hotBucketTimeRefreshInterval streamingTargetTsidxSyncPeriodMsec suspendHotRollByDeleteQuery
syn keyword confIndexes lastChanceIndex enableDataIntegrityControl journalCompression minHotIdleSecsBeforeForceRoll
syn keyword confIndexes vix.env.HUNK_THIRDPARTY_JARS vix.output.buckets.max.network.bandwidth vix.unified.search.cutoff_sec
syn keyword confIndexes enableTsidxReduction tsidxReductionCheckPeriodInSec timePeriodInSecBeforeTsidxReduction

syn match   confIndexes /\v<vix\.(family|mode|command|mapred\.job\.tracker|fs\.default\.name|splunk\.impersonation|provider)>/
syn match   confIndexes /\v<vix\.mapred\.(job\.(reuse\.jvm\.num\.tasks|queue\.name|(map|reduce)\.memory\.mb))>/
syn match   confIndexes /\v<vix\.mapred\.(child\.java\.opts|reduce\.tasks)>/
syn match   confIndexes /\v<vix\.mapreduce\.(job\.(jvm\.numtasks|reduces|queuename)|map\.(java\.opts|memory\.mb)|reduce\.(java\.opts|memory\.mb))>/
syn match   confIndexes /\v<vix\.command\.arg\.\d+>/
syn match   confIndexes /\v<vix\.\w+>/
syn match   confIndexes /\v<vix\.(env|javaprops)\.\S+>/
syn match   confIndexes /\v<vix\.splunk\.(setup\.(onsearch|package)|home\.(datanode|hdfs)|jars)>/
syn match   confIndexes /\v<vix\.splunk\.search\.(debug|recordreader|splitter)>/
syn match   confIndexes /\v<vix\.splunk\.search\.mr\.(threads|(max|min)splits|splits\.multiplier|poll)>/
syn match   confIndexes /\v<vix\.splunk\.search\.mr\.mapper\.output\.(replication|gzlevel)>/
syn match   confIndexes /\v<vix\.splunk\.search\.(mixedmode(\.maxstream)?|column\.filter)>/
syn match   confIndexes /\v<vix\.splunk\.setup\.(bundle|package)\.replication>/
syn match   confIndexes /\v<vix\.splunk\.setup\.bundle\.(max\.inactive\.wait|poll\.interval|setup\.timelimit)>/
syn match   confIndexes /\v<vix\.splunk\.setup\.package\.(max\.inactive\.wait|poll\.interval|setup\.timelimit)>/
syn match   confIndexes /\v<vix\.kerberos\.(principal|keytab)>/
syn match   confIndexes /\v<vix\.splunk\.heartbeat(\.path|\.interval|\.threshold)?>/
syn match   confIndexes /\v<vix\.splunk\.search\.recordreader\.(sequence\.ignore\.key|(csv|sequence|avro)\.regex)>/
syn match   confIndexes /\v<vix\.splunk\.search\.splitter\.(parquet\.simplifyresult)>/
syn match   confIndexes /\v<vix\.splunk\.search\.splitter\.hive\.(ppd|fileformat|(db|table)name|column(names|types))>/
syn match   confIndexes /\v<vix\.splunk\.search\.splitter\.hive\.(serde(\.properties)?|fileformat\.inputformat)>/
syn match   confIndexes /\v<vix\.splunk\.search\.splitter\.hive\.rowformat\.((fields|lines|mapkeys|collectionitems)\.terminated|escaped)>/
syn match   confIndexes /\v<vix\.input\.\d+\.(path|accept|ignore|required\.fields)>/
syn match   confIndexes /\v<vix\.input\.\d+\.(et|lt)\.(regex|format|offset|timezone|value)>/
syn match   confIndexes /\v<vix\.output\.buckets\.(path|older\.than|from\.indexes)>/
syn match   confIndexes /\v<(recordreader|splitter)\.\w+\.\w+>/
syn match   confIndexes /\v<recordreader\.(journal\.buffer\.size|csv\.dialect)>/
syn match   confIndexes /\v<splitter\.file\.split\.(min|max)size>/
syn match   confIndexes /\v<rtRouter(Threads|QueueSize)>/

syn keyword confIndexes_Constants auto_high_volume auto disable excel excel-tab tsv textfile sequencefile rcfile orc gzip lz4
syn keyword confIndexes_Constants stream report infinite

" inputs.conf
syn match   confInputsStanzas contained /\v<(tcp(-ssl)?|splunktcp(-ssl)?|monitor|batch|udp|fifo|script|fschange|filter|WinEventLog|(ad|perf)mon):[^\]]+>/
syn match   confInputsStanzas contained /\v<(default|SSL|splunktcp)>/
syn keyword confInputs host index source sourcetype queue _raw _meta _time
syn keyword confInputs crcSalt initCrcLength ignoreOlderThan
syn keyword confInputs alwaysOpenFile recursive dedicatedFD
syn keyword confInputs move_policy connection_host queueSize persistentQueueSize
syn keyword confInputs requireHeader listenOnIPv6 acceptFrom rawTcpDoneTimeout route compressed
syn keyword confInputs enableS2SHeartbeat s2sHeartbeatTimeout inputShutdownTimeout
syn keyword confInputs serverCert password rootCA requireClientCert supportSSLV3Only cipherSuite
syn keyword confInputs _rcvbuf no_priority_stripping no_appending_timestamp interval passAuth
syn keyword confInputs signedaudit filters recurse followLinks pollPeriod hashMaxSize fullEvent
syn keyword confInputs sendEventMaxSize filesPerDelay delayInMills regex
syn keyword confInputs disabled start_from current_only checkpointInterval evt_resolve_ad_obj
syn keyword confInputs negotiateNewProtocol concurrentChannelLimit batch_size
syn keyword confInputs start_by_shell object counters instances samplingInterval stats showZeroValue
syn keyword confInputs suppress_text printSchema remoteAddress process user addressFamily packetType direction
syn keyword confInputs protocol readInterval multikvMaxEventCount multikvMaxTimeMs table
syn keyword confInputs stopAcceptorAfterQBlock sslVersions sslQuietShutdown send_index_as_argument_for_path
syn keyword confInputs mode useEnglishOnly renderXml targetDc startingNode monitorSubtree printSchema baseline proc
syn keyword confInputs hive type baseline_interval multiline_event_extra_waittime dhfile outputgroup enableSSL
syn keyword confInputs useDeploymentServer indexes formatString evt_resolve_ad_ds 
syn keyword confInputs ackIdleCleanup maxIdleTime channel_cookie
syn match   confInputs /\v<_(TCP|SYSLOG|INDEX_AND_FORWARD)_ROUTING>/
syn match   confInputs /\v<host_(regex|segment)>/
syn match   confInputs /\v<(white|black)list|_(white|black)list>/
syn match   confInputs /\v<follow(Tail|Symlink)>/
syn match   confInputs /\v<(driver|user)BufferSize>/
syn match   confInputs /\v<output\.(format|timestamp(\.column|\.format)?)>/
syn match   confInputs /\v<(white|black)list[1-9]>/
syn match   confInputs /\v<evt_(ad|sid)_cache_(disabled|exp(_neg)?|max_entries)>/
syn match   confInputs /\v<evt_(dns|dc)_name>/
syn match   confInputs /\v<sid_cache_(disabled|exp(_neg)?|max_entries)>/
syn match   confInputs /\v<ecdhCurve(Name|s)>/

syn keyword confInputs_Constants ip dns single multikv

" instance.cfg
syn match   confInstanceStanzas contained /\v<general>/
syn keyword confInstance guid

" launcher.conf
syn match   confLauncherStanzas contained /\v<settings>/
syn keyword confLauncher welcome_apps

" ldap.conf from SA-ldapsearch
syn match   confSALDAPStanzas contained /\v<default>/
syn keyword confSALDAP alternatedomain basedn server ssl port binddn password decode paged_size

" logging.conf from SA-ldapsearch
syn match   confSALDAPLoggingStanzas contained /\v<loggers|logger_root|handlers|formatters|handler_(\S+)|formatter_(\S+)>/
syn keyword confSALDAPLogging keys level handlers qualname propagate args class formatter datefmt format
syn keyword confSALDAPLogging_Constants critical error warning info debug notset

" ssl.conf from SA-ldapsearch
syn match   confSALDAPSSLStanzas contained /\v<sslConfig>/
syn keyword confSALDAPSSL sslVersions sslVerifyServerCert caCertFile caPath

" limits.conf
syn match   confLimitsStanzas contained /\v<(anomalousvalue|associate|authtokens|auto_summarizer|autoregress|concurrency)>/
syn match   confLimitsStanzas contained /\v<(correlate|ctable|default|discretize|export|extern|indexpreview)>/
syn match   confLimitsStanzas contained /\v<(input(_channels|csv|proc)|join|journal_compress|kmeans|kv|ldap|lookup)>/
syn match   confLimitsStanzas contained /\v<(metadata|metrics|pdf|rare|realtime|restapi|reversedns|sample|scheduler)>/
syn match   confLimitsStanzas contained /\v<(search(results)?|set|show_source|sistats|slc|sort|spath|stats|subsearch)>/
syn match   confLimitsStanzas contained /\v<(summarize|thruput|top|transactions|tscollect|typeahead|typer|viewstates)>/
syn keyword confLimits perf_warn_limit mkdir_max_retries ttl DelayArchiveProcessorShutdown
syn keyword confLimits soft_preview_queue_size suppress_derived_info limit
syn keyword confLimits batch_index_query aggregate_metrics summary_mode 
syn keyword confLimits batch_response_limit interval jobscontentmaxcount
syn keyword confLimits truncate_report debug_metrics base_max_searches 
syn keyword confLimits target_time_perchunk long_search_threshold realtime_buffer stack_size 
syn keyword confLimits fieldstats_update_maxperiod remote_timeline 
syn keyword confLimits track_indextime_range reuse_map_maxsize force_saved_search_dispatch_as_user
syn keyword confLimits search_process_mode fetch_remote_search_log
syn keyword confLimits load_remote_bundles check_splunkd_period queue_size blocking 
syn keyword confLimits indexfilter list_maxsize enforce_time_order disk_usage_update_period
syn keyword confLimits perc_method approx_dc_threshold
syn keyword confLimits dc_digest_bits natural_sort_output threads hot_bucket_min_new_events
syn keyword confLimits sleep_seconds stale_lock_seconds indexed_as_exact_metasearch
syn keyword confLimits indextime_lag maxopentxn maxopenevents time_before_close tailing_proc_speed
syn keyword confLimits auto_summary_perc action_execution_threads persistance_period 
syn keyword confLimits maintenance_period verify_delete scheduled_view_timeout 
syn keyword confLimits distributed distributed_search_limit result_queue_max_size
syn keyword confLimits fetch_multiplier render_endpoint_timeout timeline_events_preview
syn keyword confLimits inactive_eligibility_age_seconds expiration_time lowater_inactive
syn keyword confLimits extraction_cutoff extract_all rdnsMaxDutyCycle 
syn keyword confLimits squashcase keepresults tsidx_init_file_goal_mb
syn keyword confLimits optimize_period optimize_min_src_count optimize_max_size_mb
syn keyword confLimits remote_timeline_prefetch remote_timeline_parallel_fetch
syn keyword confLimits do_not_use_summaries monitornohandle_max_heap_mb
syn keyword confLimits batch_wait_after_end write_multifile_results_out unified_search
syn keyword confLimits partitions_limit return_actions_with_normalized_ids normalized_summaries
syn keyword confLimits detailed_dashboard maxzoomlevel filterstrategy
syn keyword confLimits apply_search_filter summariesonly compression_level infocsv_log_level
syn keyword confLimits file_tracking_db_threshold_mb alerting_period_ms db_path 
syn keyword confLimits remote_reduce_limit search_2_hash_cache_timeout installed_files_integrity
syn keyword confLimits shp_dispatch_to_slave protect_dispatch_folders insufficient_search_capabilities
syn keyword confLimits show_warn_on_filtered_indexes filteredindexes_log_level failed_job_ttl
syn keyword confLimits learned_sourcetypes_limit saved_searches_disabled concurrency_message_throttle_time 
syn keyword confLimits warn_on_missing_summaries introspection_lookback sync_bundle_replication
syn keyword confLimits metrics_report_interval batch_search_activation_fraction sensitivity
syn keyword confLimits packets_per_data_point grace_period_before_disconnect orphan_searches
syn keyword confLimits bound_on_disconnect_threshold_as_fraction_of_mean addpeer_skew_limit
syn match   confLimits /\v<idle_process_(cache_(search_count|timeout)|reaper_period|regex_cache_hiwater)>/
syn match   confLimits /\v<actions_queue_(size|timeout)|sparkline_(maxsize|time_steps)>/
syn match   confLimits /\v<add_(timestamp|offset)|(min|max)_preview_period>/
syn match   confLimits /\v<allow_(batch_mode|event_summarization|inexact_metasearch|multiple_matching_users|old_summaries|reuse)>/
syn match   confLimits /\v<alerts_(expire_period|max_(count|history)|scoping)>/
syn match   confLimits /\v<(auto_summary|max_searches)_perc\.\d+(\.when)?>/
syn match   confLimits /\v<(auto_summary_perc|max_searches_perc)\.\d+\.when>/
syn match   confLimits /\v<batch_retry_((min|max)_interval|scaling)>/
syn match   confLimits /\v<batch_search_max_(index_values|pipeline|(results_aggregator|serialized_results)_queue_size)>/
syn match   confLimits /\v<cache_(ttl(_sec)?|timeout)>/
syn match   confLimits /\v<chunk_(multiplier|size)>/
syn match   confLimits /\v<(default_save|remote|cache)_ttl>/
syn match   confLimits /\v<default_(allow_queue|backfill|partitions|save_ttl|time_bins)>/
syn match   confLimits /\v<dispatch_(dir_warning_size|quota_(retry|sleep_ms))>/
syn match   confLimits /\v<enable_(clipping|cumulative_quota|datamodel_meval|generalization|history|memory_tracker|reaper|status_cache|expanded_search_pruning)>/
syn match   confLimits /\v<indexed_realtime_(use_by_default|disk_sync_delay|cluster_update_interval|(maximum|default)_span)>/
syn match   confLimits /\v<launcher_(threads|max_idle_checks)>/
syn match   confLimits /\v<local_(connect|send|receive)_timeout>/
syn match   confLimits /\v<(max|avg)_extractor_time>/
syn match   confLimits /\v<max(time|value(s|size)|fields|p|range|out|resultrows|bins|datapoints|kvalue|files)>/
syn match   confLimits /\v<max(krange|cols|chars|series|batch_size_bytes|KBps|clusters|len|count|(total)?samples)>/
syn match   confLimits /\v<max_(accelerations_per_collection|action_results|blocking_secs|bucket_bytes|chunk_queue_size)>/
syn match   confLimits /\v<max_(combiner_memevents|concurrent_per_user|content_length|continuous_scheduled_search_lookback)>/
syn match   confLimits /\v<max_(count|documents_per_batch_save|events_per_bucket|fd|fields_per_acceleration|history_length)>/
syn match   confLimits /\v<max_(id_length|inactive|infocsv_messages|lock_files|lock_file_ttl|lookup_messages|macro_depth)>/
syn match   confLimits /\v<max_(hot_bucket_summarization|replicated_hot_bucket)_idle_time>/
syn match   confLimits /\v<max_(matches|memtable_bytes|mem_usage_mb|number_of_tokens|per_result_alerts(_time)?|preview_bytes|threads_per_outputlookup)>/
syn match   confLimits /\v<max_number_of_(ack_channel|acked_(requests_pending_query(_per_ack_channel)?))>/
syn match   confLimits /\v<max_(queries_per_batch|(rawsize|results)_perchunk|reverse_matches)>/
syn match   confLimits /\v<max_rows_(in_memory_per_dump|per_(query|table))>/
syn match   confLimits /\v<max_(rt_search_multiplier|run_stats|searches_(perc|per_cpu))>/
syn match   confLimits /\v<max_size_per_((batch_(result|save)|result)_mb)>/
syn match   confLimits /\v<max_(stream_window|subsearch_depth|tolerable_skew|users_to_precache|valuemap_bytes|summary_(ratio|size)|old_bundle_idle_time)>/
syn match   confLimits /\v<max_time(after|before)?>/
syn match   confLimits /\v<max_(time|searches)_per_process>/
syn match   confLimits /\v<max_(verify_(buckets|bucket_time|ratio|total_time)|workers_searchparser)>/
syn match   confLimits /\v<min_(prefix_len(gth)?|results_perchunk|freq|batch_size_bytes)>/
syn match   confLimits /\v<priority_(runtime|skipped)_factor>/
syn match   confLimits /\v<process_(max_age|min_age_before_user_change)>/
syn match   confLimits /\v<rr_((min|max)_sleep_ms|sleep_factor)>/
syn match   confLimits /\v<rdigest_(k|maxnodes)>/
syn match   confLimits /\v<reaper_(freq|soft_warn_level)>/
syn match   confLimits /\v<(reduce|preview)_duty_cycle>/
syn match   confLimits /\v<(reduce|maxmem_check|timeline|preview|fieldstats_update|queued_job_check)_freq>/
syn match   confLimits /\v<remote_event_download_(finalize|initialize|local)_pool>/
syn match   confLimits /\v<remote_timeline_(min_peers|fetchall|thread|max_count|max_size_mb|touchperiod)>/
syn match   confLimits /\v<remote_timeline_((connection|send|receive)_timeout)>/
syn match   confLimits /\v<replication_(file_ttl|period_sec)>/
syn match   confLimits /\v<results_queue_(max|min)_size>/
syn match   confLimits /\v<search_history_(max_runtimes|load_timeout)>/
syn match   confLimits /\v<search_process_memory_usage_(percentage_)?threshold>/
syn match   confLimits /\v<shc_(accurate_access_counts|local_quota_check|role_quota_enforcement)>/
syn match   confLimits /\v<threshold_(data_volume|connection_life_time)>/
syn match   confLimits /\v<time_(before_close|format_reject)>/
syn match   confLimits /\v<tocsv_(maxretry|retryperiod_ms)>/
syn match   confLimits /\v<use_(bloomfilter|cache|dispatchtmp_dir)>/
syn match   confLimits /\v<status_(period_ms|cache_(size|in_memory_ttl)|buckets)>/
syn match   confLimits /\v<subsearch_(max(out|time)|timeout)>/
syn match   confLimits /\v<zl_0_gridcell_(lat|long)span>/

syn keyword confLimits_Constants DEBUG INFO WARN ERROR traditional debug nearest-rank interpolated splunk_server disabledSavedSearches log_only

" livetail.conf
syn keyword confLivetail threshold playsound sound flash color keyphrase enabled
syn match   confLivetail /\v<sound-(ding|airhorn|alarm)>/

" macros.conf
"syn keyword confMacrosStanzas
syn keyword confMacros args definition validation errormsg iseval description

" messages.conf
syn keyword confMessages name message action severity capabilities help
syn keyword confMessagesConstants critical error warn info debug
" *.meta
syn match confMetaStanzas contained /\v<(views(\/[^\]]+)?|transforms|exports|savedsearches|macros|eventtypes)>/
syn keyword confMeta access export owner
syn keyword confMeta_Constants system admin power read write none

" multikv.conf
"syn keyword confMultikvStanzas
syn match   confMultikv /\v<(pre|header|body|post)\.(start(_offset)?|end|member|linecount|ignore|replace|tokens)>/
syn keyword confMultikv _chop_ _tokenize_ _align_ _token_list_ _regex_ _all_ _none_

" outputs.conf
syn match   confOutputsStanzas contained /\v<(default|tcpout((-server)?:[^\]]+)?|syslog(:[^\]]+)?|indexAndForward)>/
syn keyword confOutputs defaultGroup indexAndForward server sendCookedData heartbeatFrequency
syn keyword confOutputs blockOnCloning compressed dnsResolutionInterval tlsHostname
syn keyword confOutputs forceTimebasedAutoLB .whitelist .blacklist tcpSendBufSz
syn keyword confOutputs forwardedindex.filter.disable ackTimeoutOnShutdown useClientSSLCompression
syn keyword confOutputs useACK type priority syslogSourceType timestampformat selectiveIndexing
syn keyword confOutputs masterUri blockWarnThreshold negotiateNewProtocol 
syn keyword confOutputs backoffOnFailure indexerDiscovery secsInFailureInterval 
syn match   confOutputs /\v<autoLB(Frequency)?>/
syn match   confOutputs /\v<channel(TTL|Reap(Interval|Lowater))>/
syn match   confOutputs /\v<(connection|read|write)Timeout>/
syn match   confOutputs /\v<drop((Cloned)?Events)OnQueueFull>/
syn match   confOutputs /\v<forwardedindex\.\d\.(whitelist|blacklist)>/
syn match   confOutputs /\v<max((Event|Queue)Size|ConnectionsPerIndexer|FailuresPerInterval)>/
syn match   confOutputs /\v<socks(Server|Username|Password|ResolveDNS)>/
syn match   confOutputs /\v<ssl(Password|(Cert|RootCA)Path|Cipher|VerifyServerCert|(Common|Alt)NameToCheck|QuietShutdown)>/

syn keyword confOutputs_Constants NO_PRI tcp udp local

" passwords.conf
syn keyword confPasswords password

" pdf_server.conf
syn match   confPDFserverStanzas contained /\v<(settings)>/
syn keyword confPDFserver startwebserver httpport enableSplunkWebSSL 
syn keyword confPDFserver supportSSLV3Only static_dir enable_gzip screenshot_enabled
syn keyword confPDFserver request.show_tracebacks engine.autoreload_on response.timeout 
syn keyword confPDFserver pid_path firefox_cmdline Xvfb xauth mcookie
syn match   confPDFserver /\v<(appserver|client)_ipaddr>/
syn match   confPDFserver /\v<(caCert|privKey)Path>/
syn match   confPDFserver /\v<log\.(screen|(access|error)_file)>/
syn match   confPDFserver /\v<max_(concurrent|queue)>/
syn match   confPDFserver /\v<server\.(socket_host|thread_pool)>/
syn match   confPDFserver /\v<(static|root)_endpoint>/
syn match   confPDFserver /\v<tools\.(sessions\.(on|timeout|storage_(type|path))|decode\.on|encode\.(on|encoding))>/

" procmon-filters.conf
"syn keyword confProcmonFiltersStanzas
syn keyword confProcmonFilters proc type hive

" props.conf
syn match   confPropsStanzas contained /\v<(default|(rule|source|delayedrule|host)::[^\]]+)>/
syn keyword confProps host source sourcetype CHARSET TRUNCATE LINE_BREAKER LINE_BREAKER_LOOKBEHIND
syn keyword confProps NO_BINARY_CHECK SEGMENTATION DATETIME_CONFIG SHOULD_LINEMERGE MUST_BREAK_AFTER
syn keyword confProps initCrcLength PREFIX_SOURCETYPE sourcetype rename invalid_cause is_valid
syn keyword confProps LEARN_SOURCETYPE LEARN_MODEL maxDist 
syn keyword confProps ANNOTATE_PUNCT HEADER_MODE _actions pulldown_type
syn keyword confProps given_type INDEXED_EXTRACTIONS PREAMBLE_REGEX 
syn keyword confProps TIMESTAMP_FIELDS detect_trailing_nulls
syn keyword confProps category MISSING_VALUE_REGEX AUTO_KV_JSON JSON_TRIM_BRACES_IN_ARRAY_NAMES
syn match   confProps /\v<BREAK_ONLY_BEFORE(_DATE)?|EVENT_BREAKER(_ENABLE)?>/
syn match   confProps /\v<CHECK_(FOR_HEADER|METHOD)>/
syn match   confProps /\v<FIELD_(DELIMITER|HEADER_REGEX|NAMES|QUOTE)>/
syn match   confProps /\v<HEADER_FIELD_(LINE_NUMBER|DELIMITER|QUOTE)>/
syn match   confProps /\v<KV_(MODE|TRIM_SPACES)>/
syn match   confProps /\v<MAX_(DAYS_(AGO|HENCE)|DIFF_SECS_(AGO|HENCE)|EVENTS|TIMESTAMP_LOOKAHEAD)>/
syn match   confProps /\v<MUST_NOT_BREAK_(AFTER|BEFORE)>/
syn match   confProps /\v<TIME_(FORMAT|PREFIX)>/
syn match   confProps /\v<TZ(_ALIAS)?>/
syn match   confProps /\v<unarchive_(cmd|sourcetype)>/

syn keyword confProps_Constants none auto auto_escaped multi json xml firstline CSV W3C TSV PSV JSON
syn keyword confProps_Constants endpoint_md5 entire_md5 modtime AS OUTPUT OUTPUTNEW

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
syn keyword confRestmap pythonHandlerPath match requireAuthentication capability
syn keyword confRestmap xsl script output_modes members showInDirSvc desc dynamic path untar
syn keyword confRestmap includeInAccessLog authKeyStanza defaultRestReplayStanza passSystemAuth destination
syn keyword confRestmap filternodes
syn match   confRestmap /\v<allow(GetAuth|RestReplay)>/
syn match   confRestmap /\v<capability\.(delete|get|post|put)>/
syn match   confRestmap /\v<handler(actions|file|persistentmode|type)?>/
syn match   confRestmap /\v<node(s|lists)>/
syn match   confRestmap /\v<restReplay(Stanza)?>/
syn match   confRestmap /\v<script(type|\.arg\.\d|\.param)?>/
syn match   confRestmap /\v<driver(\.arg\.\d|\.env\.\w+)?>/
syn match   confRestmap /\v<pass(Conf|Payload|Session|Http(Headers|Cookies))>/

" savedsearches.conf
syn match   confSavedSearchesStanzas contained /\v<(default)>/
syn keyword confSavedSearches disabled search enableSched cron_schedule max_concurrent dispatchAs embed.enabled
syn keyword confSavedSearches realtime_schedule counttype relation quantity alert_condition action_rss displayview nextrun
syn keyword confSavedSearches qualifiedSearch query restart_on_searchpeer_add role run_n_times run_on_startup userid vsid action_email
syn match   confSavedSearches /\v<action\.email(\.cc|\.format|\.from|\.inline|\.mailserver|\.maxresults|\.message.alert|\.message\.report|\.priority|\.reportServerEnabled|\.sendcsv|\.sendpdf|\.sendresults|\.subject|\.subject.alert|\.subject\.report|\.to|\.useNSSubject)?>/
syn match   confSavedSearches /\v<action\.email\.include\.(results_link|search|trigger(_time)?|view_link)>/
syn match   confSavedSearches /\v<action\.name(\.parameter)?>/
syn match   confSavedSearches /\v<action\.populate_lookup(\.dest)?>/
syn match   confSavedSearches /\v<action\.script(\.filename)?>/
syn match   confSavedSearches /\v<action\.summary_index(\.inline|\._name|\.\w+)?>/
syn match   confSavedSearches /\v<alert\.(digest_mode|display_view|expires|severity|suppress(\.fields|\.period)?|track)>/
syn match   confSavedSearches /\v<auto_summarize(\.command|\.cron_schedule|\.dispatch\.\w+|\.hash)?>/
syn match   confSavedSearches /\v<auto_summarize\.max_(concurrent|disabled_buckets|summary_(ratio|size)|time)>/
syn match   confSavedSearches /\v<auto_summarize(\.normalized_hash|\.suspend_period|\.timespan)>/
syn match   confSavedSearches /\v<dispatch\.(auto_(cancel|pause)|buckets|earliest_time|index(_earliest|edRealtime(Offset|MinSpan)?|_latest)|rt_maximum_span)>/
syn match   confSavedSearches /\v<dispatch\.(lookups|max_(count|time)|reduce_freq|rt_backfill|spawn_process|time_format|ttl|sample_ratio)>/
syn match   confSavedSearches /\v<display\.events\.(fields|list\.(drilldown|wrap)|maxLines|raw\.drilldown|rowNumbers)>/
syn match   confSavedSearches /\v<display\.events\.(table\.(drilldown|wrap)|type)>/
syn match   confSavedSearches /\v<display\.general\.(enablePreview|locale|migratedFromViewState|timeRangePicker\.show|type)>/
syn match   confSavedSearches /\v<display\.page\.(pivot\.dataModel)>/
syn match   confSavedSearches /\v<display\.page\.search\.(mode|patterns\.sensitivity|showFields|tab|timeline\.(format|scale))>/
syn match   confSavedSearches /\v<display\.statistics\.(drilldown|overlay|rowNumbers|show|wrap|(totals|percentages)Row)>/
syn match   confSavedSearches /\v<display\.statistics\.format\.\w+(\.field(s)?|\.scale(\.categories|\.base|\.(min|mid|max)(Type|Value)|\.thresholds)?|\.colorPalette|\.precision|\.useThousandSeparators|\.unit(Position)?)?>/
syn match   confSavedSearches /\v<display\.statistics\.format\.\w+\.colorPalette\.(rule|colors|interpolate|(min|mid|max)Color)>/
syn match   confSavedSearches /\v<display\.visualizations\.chartHeight>/
syn match   confSavedSearches /\v<display\.visualizations\.charting\.axisLabels(X\.majorLabelStyle\.(overflowMode|rotation)|X\.majorUnit)>/
syn match   confSavedSearches /\v<display\.visualizations\.charting\.axisLabelsY((2)?\.majorUnit)>/
syn match   confSavedSearches /\v<display\.visualizations\.charting\.axisTitleX\.(text|visibility)>/
syn match   confSavedSearches /\v<display\.visualizations\.charting\.axisTitleY((2)?\.visibility|(2)?\.text)>/
syn match   confSavedSearches /\v<display\.visualizations\.charting\.axisX\.((max|min)imumNumber|scale)>/
syn match   confSavedSearches /\v<display\.visualizations\.charting\.axisY2\.(enabled|(max|min)imumNumber|scale)>/
syn match   confSavedSearches /\v<display\.visualizations\.charting\.axisY\.(enabled|(max|min)imumNumber|scale)>/
syn match   confSavedSearches /\v<display\.visualizations\.charting\.chart\.bubble((Max|Min)imumSize|SizeBy)>/
syn match   confSavedSearches /\v<display\.visualizations\.charting\.chart(\.nullValueMode|\.overlayFields|\.rangeValues)>/
syn match   confSavedSearches /\v<display\.visualizations\.charting\.chart\.(showDataLabels|sliceCollapsingThreshold|stackMode|style)>/
syn match   confSavedSearches /\v<display\.visualizations\.charting\.(drilldown|gaugeColors|layout\.(splitSeries(\.allowIndependentYRanges)?))>/
syn match   confSavedSearches /\v<display\.visualizations\.charting\.legend\.(labelStyle\.overflowMode|placement)>/
syn match   confSavedSearches /\v<display\.visualizations\.custom\.(height|type)>/
syn match   confSavedSearches /\v<display\.visualizations\.(mapHeight|show|singlevalueHeight)>/
syn match   confSavedSearches /\v<display\.visualizations\.mapping\.choroplethLayer\.color(Bins|Mode)>/
syn match   confSavedSearches /\v<display\.visualizations\.mapping\.choroplethLayer\.((max|min)imumColor|neutralPoint|shapeOpacity|showBorder)>/
syn match   confSavedSearches /\v<display\.visualizations\.mapping\.(data\.maxClusters|drilldown|showTiles|type)>/
syn match   confSavedSearches /\v<display\.visualizations\.mapping\.map\.(center|panning|scrollZoom|zoom)>/
syn match   confSavedSearches /\v<display\.visualizations\.mapping\.markerLayer\.marker((Max|Min)Size|Opacity)>/
syn match   confSavedSearches /\v<display\.visualizations\.mapping\.tileLayer\.((max|min)Zoom|tileOpacity|url)>/
syn match   confSavedSearches /\v<display\.visualizations\.singlevalue\.((after|before)Label|color(By|Mode))>/
syn match   confSavedSearches /\v<display\.visualizations\.singlevalue\.(numberPrecision|range(Colors|Values)|show(Sparkline|TrendIndicator))>/
syn match   confSavedSearches /\v<display\.visualizations\.singlevalue\.(trend(ColorInterpretation|DisplayMode|Interval)|underLabel|unit(Position)?|drilldown)>/
syn match   confSavedSearches /\v<display\.visualizations\.singlevalue\.use(Colors|ThousandSeparators)>/
syn match   confSavedSearches /\v<request\.ui_dispatch_(app|view)>/
syn match   confSavedSearches /\v<schedule(_window|_priority)?>/

syn keyword confSavedSearches_Constants fast smart verbose hidden compact full linear log events statistics visualizations
syn keyword confSavedSearches_Constants heatmap highlow stacked default stacked100 right bottom top left visible collapsed
syn keyword confSavedSearches_Constants mapping embed.enabled diameter bubble gaps zero connect ellipsisNone user owner
syn keyword confSavedSearches_Constants patterns all minmax percent absolute standard inverse marker choropleth sequential divergent categorical block inherit

" alert_logevent
" savedsearches.conf
syn match   confSavedSearches /\v<action\.(logevent(\.param\.(event|host|source(type)?|index))|log_event)>/

" searchbnf.conf
syn match   confSearchbnfStanzas contained /\v<(default|[^-]+\-(command|options))>/
syn case ignore
syn keyword confSearchbnf syntax simplesyntax alias description shortdesc usage tags
syn keyword confSearchbnf related maintainer appears-in note supports-multivalue optout-in
syn match   confSearchbnf /\v<(example|comment)\d*>/
syn case match

syn keyword confSearchbnf_Constants public private deprecated

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
syn keyword confServer sessionTimeout trustedIP pass4SymmKey listenOnIPv6
syn keyword confServer connectUsingIpVersion guid supportSSLV3Only 
syn keyword confServer requireClientCert cipherSuite components 
syn keyword confServer certCreateScript atomFeedStylesheet
syn keyword confServer max-age follow-symlinks acceptFrom streamInWriteTimeout
syn keyword confServer ssl url detailsUrl mode requireBootPassphrase
syn keyword confServer initialNumberOfScriptProcesses minFreeSpace
syn keyword confServer outputQueue master_uri active_group connection_timeout 
syn keyword confServer receive_timeout squash_threshold description quota slaves stack_id storage
syn keyword confServer rep_cxn_timeout rep_send_timeout rep_rcv_timeout search_factor
syn keyword confServer restart_timeout quiet_period generation_poll_interval
syn keyword confServer defaultHTTPServerCompressionLevel skipHTTPCompressAcl sendStrictTransportSecurityHeader
syn keyword confServer forceHttp10 crossOriginSharingPolicy
syn keyword confServer x_fram_options_sameorigin cliLoginBanner basicAuthRealm 
syn keyword confServer sampling_interval app_update_triggers search_files_retry_timeout
syn keyword confServer target_wait_time commit_retry_time percent_peers_to_restart executor_workers
syn keyword confServer acquireExtra_i_data adhoc_searchhead re_add_on_bucket_request_error
syn keyword confServer alert_proxying all_dumps async_replicate_on_proxy rebalance_threshold
syn keyword confServer auto_rebalance_primaries available_sites site_mappings max_auto_service_interval manual_detention useSSLCompression preferred_captain
syn keyword confServer retry_autosummarize_or_data_model_acceleration_jobs
syn keyword confServer dbPath distributedLookupTimeout upload_proto_host_port
syn keyword confServer embedSecret etc_filesize_limit hangup_after_phonehome
syn keyword confServer hostnameOption idle_connections_pool_size initAttempts instanceType
syn keyword confServer long_running_jobs_poll_period master_dump_service_periods
syn keyword confServer mgmt_uri multisite oplogSize pool_suggestion prefix profilingStatsCollectionPeriodInSecs
syn keyword confServer ra_proxying replicaset report_interval BackupIndex checkFrequency
syn keyword confServer rsStatsCollectionPeriodInSecs scheduling_heuristic shutdownTimeout
syn keyword confServer sid_proxying skipHTTPCompressionAcl ss_proxying
syn keyword confServer strict_pool_quota parallelIngestionPipelines dhFile
syn keyword confServer advertised_disk_capacity throwOnBucketBuildReadError cluster_label no_artifact_replications
syn keyword confServer rolling_restart_with_captaincy_exchange csv_journal_rows_per_hb
syn keyword confServer artifact_status_fields encrypt_fields shcluster_label 
syn keyword confServer indexerWeightByDiskCapacity notify_scan_period replicate_search_peers
syn match   confServer /\v<access_logging_for_(heartbeats|phonehome)>/
syn match   confServer /\v<allow((Basic|Cookie|EmbedToken)Auth|InternetAccess|RemoteLogin|Ssl(Compression|Renegotiation))>/
syn match   confServer /\v<ca(Cert(File|Path)|Path)>/
syn match   confServer /\v<captain_(is_adhoc_searchhead|uri)>/
syn match   confServer /\v<cntr_\d_lookback_time>/
syn match   confServer /\v<collection(StatsCollection)?PeriodInSecs>/
syn match   confServer /\v<conf_deploy_(concerning_file_size|fetch_(mode|url)|repository|staging)>/
syn match   confServer /\v<conf_replication_(include\.\w+|max_(pull|push)_count|period|purge\.(eligibile_(age|count)|period))>/
syn match   confServer /\v<conf_replication_summary\.((black|white)list\.\w+|concerning_file_size|period)>/
syn match   confServer /\v<cookieAuth(HttpOnly|Secure)>/
syn match   confServer /\v<cxn_timeout(_raft)?>/
syn match   confServer /\v<disable(d|DefaultPort)>/
syn match   confServer /\v<election(_timeout_(ms|2_hb_ratio))?>/
syn match   confServer /\v<enable(_jobs_data_lite|S2SHeartbeat|SplunkdSSL)>/
syn match   confServer /\v<heartbeat_(period|timeout)>/
syn match   confServer /\v<index_(files|listing)>/
syn match   confServer /\v<lock\.(logging|timeout)>/
syn match   confServer /\v<log(_age|_heartbeat_append_entries|inUrl)>/
syn match   confServer /\v<max_(content_length|peer_(build|(sum_)?rep)_load|replication_errors)>/
syn match   confServer /\v<max((File)?Size|Sockets|Threads)>/
syn match   confServer /\v<modifications(MaxReadSec|ReadIntervalMillisec)>/
syn match   confServer /\v<poll\.(blacklist\.\w+|interval\.(check|rebuild))>/
syn match   confServer /\v<polling((Timer)?Frequency|_rate)>/
syn match   confServer /\v<rcv_timeout(_raft)?>/
syn match   confServer /\v<register_(forwarder|replication|search)_address>/
syn match   confServer /\v<replication(_factor|_host|WriteTimeout)>/
syn match   confServer /\v<rep_max_(rcv|send)_timeout>/
syn match   confServer /\v<searchable_target(s|_sync_timeout)>/
syn match   confServer /\v<send_timeout(_raft)?>/
syn match   confServer /\v<server(Cert|Name|s_list|StatsCollectionPeriodInSecs)>/
syn match   confServer /\v<service_(interval|jobs_msec)>/
syn match   confServer /\v<site(_(replication|search)_factor)?>/
syn match   confServer /\v<ssl(AltNameToCheck|CommonName(List|ToCheck)|CRLPath|Keys(file(Password)?|Password|Path|VerifyServerCert))>/
syn match   confServer /\v<sslVersions(ForClient)?>/
syn match   confServer /\v<state(IntervalInSecs)?>/
syn match   confServer /\v<summary_(wait_time|replication)>/
syn match   confServer /\v<update(Host|Path|Timeout)>/
syn match   confServer /\v<use(_batch_mask_changes|(ClientSSL|HTTP(Client|Server))Compression|ragent|SplunkdClientSSLCompression)>/
syn match   confServer /\v<verbose(Level)?>/

syn keyword confServer_Constants always never requireSetPassword KB MB GB self Enterprise Trial Forwarder Free
syn keyword confServer_Constants master slave searchhead enabled clustermaster: silence silent replace on-http on-https
syn keyword confServer_Constants 4-first 6-first 4-only 6-only MAX

syn match confComplex /\v<EXCLUDE-\k+/

" serverclass.conf
syn match   confServerClassStanzas contained /\v<(global|serverClass:[^\]]+)>/
syn keyword confServerClass tmpFolder continueMatching stateOnClient appFile excludeFromUpdate restartIfNeeded
syn keyword confServerClass endpoint filterType crossServerChecksum issueReload precompressBundles
syn match   confServerClass /\v<(repository|target)RepositoryLocation>/
syn match   confServerClass /\v<machineTypes(Filter)?>/
syn match   confServerClass /\v<restartSplunk(d|Web)>/

syn match   confComplex /\v<(white|black)list\.\d+>/
syn match   confComplex /\v<(white|black)list\.(from_\k+|(select|where)_field|where_equals)>/

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

" splunk_monitoring_console
" splunk_monitoring_console_assets.conf

syn match   confMCAssetsStanzas contained /\v<(settings)>/
syn keyword confMCAssets disabled configuredPeers blackList host host_fqdn
syn match   confMCAssets /\v<(indexer|searchHead)Clusters>/

" tags.conf
"syn keyword confTagsStanzas
"syn keyword confTags

" telemetry.conf
syn keyword confTelemetry showOptInModal deprecatedConfig retryTransaction
syn match   confTelemetry /\v<send(License|Anonymized)Usage|precheckSend(License|Anonymized)Usage>/

" tenants.conf
syn match   confTenantsStanzas contained /\v<(default|tenant:[^\]]+)>/
syn keyword confTenants filterType whitelist. blacklist. phoneHomeTopic

" times.conf
syn match   confTimesStanzas contained /\v<(default)>/
syn keyword confTimes label header_label earliest_time latest_time order sub_menu is_sub_menu

" transactiontypes.conf
syn match   confTransactionTypesStanzas contained /\v<(default)>/
syn keyword confTransactionTypes fields startswith endswith connected
syn keyword confTransactionTypes keepevicted mvlist delim nullstr search
syn match   confTransactionTypes /\v<max(span|pause|events|open(events|txn))>/

" transforms.conf
syn match   confTransformsStanzas contained /\v<(default|accepted_keys)>/
syn keyword confTransforms REGEX FORMAT LOOKAHEAD WRITE_META DEST_KEY DEFAULT_VALUE SOURCE_KEY
syn keyword confTransforms REPEAT_MATCH DELIMS FIELDS MV_ADD CLEAN_KEYS KEEP_EMPTY_VALS CAN_OPTIMIZE
syn keyword confTransforms filename default_match case_sensitive_match batch_index_query allow_caching
syn keyword confTransforms match_type external_cmd fields_list external_type time_field time_format
syn keyword confTransforms CLONE_SOURCETYPE collection max_ext_batch filter feature_id_element
syn match   confTransforms /\v<(max|min)_matches>/
syn match   confTransforms /\v<(max|min)_offset_secs>/

syn keyword confTransforms_Constants _raw _done _meta _time MetaData:FinalType MetaData:Host queue python executable kvstore geo
syn keyword confTransforms_Constants _MetaData:Index MetaData:Source MetaData:Sourcetype

syn match confComplex /\v<_(KEY|VAL)_\k+>/

" ui-prefs.conf
syn match   confUIPrefsStanzas contained /\v<(default)>/
syn keyword confUIPrefs display.general.enablePreview display.page.home.showGettingStarted display.visualizations.chartHeight
syn keyword confUIPrefs display.visualizations.type countPerPage
syn match   confUIPrefs /\v<dispatch\.(earliest|latest)_time>/
syn match   confUIPrefs /\v<display\.events\.(fields|list\.(drilldown|wrap)|maxLines|raw\.drilldown|rowNumbers)>/
syn match   confUIPrefs /\v<display\.events\.(table\.(drilldown|wrap)|type)>/
syn match   confUIPrefs /\v<display\.page\.search\.(mode|patterns\.sensitivity|searchHistoryTimeFilter|showFields|tab|timeline\.(format|scale))>/
syn match   confUIPrefs /\v<display\.prefs\.((acl|app)Filter|autoOpenSearchAssistant|customSampleRatio|showSPL|enableMetaData|events\.count|fieldCoverage|listMode|livetail)>/
syn match   confUIPrefs /\v<display\.prefs\.(searchContext|showDataSummary|statistics\.count|timeline\.(height|minimalMode|minimized))>/
syn match   confUIPrefs /\v<display\.statistics\.(drilldown|rowNumbers|wrap)>/
syn match   confUIPrefs /\v<display\.visualizations\.charting\.(chart(\.style)?|legend\.labelStyle\.ovelflowMode)>/

syn keyword confUIPrefs_Constants none app owner raw list table inner outer full row cell charting singlevalue line area column bar pie
syn keyword confUIPrefs_Constants minimal shiny fast smart hidden compact full linear log tiles scatter verbose
syn match   confUIPrefs_Constants /\v<(filler|marker|radial)Gauge>/
syn match   confUIPrefs_Constants /\v<ellipsis(End|Middle|Start)>/

" ui-tour.conf
syn match   confUITourStanzas contained /\v<()>/
syn keyword confUITour intro type label tourPage viewed imgPath context urlData 
syn match   confUITour /\v<(next|use)Tour>/
syn match   confUITour /\v<image(Caption|Name)>/
syn match   confUITour /\v<step(Click(Element|Event)|Element|Position|Text)\d>/

syn keyword confUITour_Constants image interactive system bottom right left top click mousedown mouseup

" user-prefs.conf
syn match   confUserPrefsStanzas contained /\v<(general|default)>/
syn keyword confUserPrefs tz install_source_checksum lang search_syntax_highlighting
syn keyword confUserPrefs search_assistant datasets:showInstallDialog
syn match   confUserPrefs /\v<default_(namespace|(earliest|latest)_time)>/
syn match   confUserPrefs /\v<infodelivery_(enabled|show_(ad|configure)_modal)>/

" user-seed.conf
syn match   confUserSeedStanzas contained /\v<(user_info)>/
syn keyword confUserSeed USERNAME PASSWORD

" viewstates.conf
syn match   confViewStatesStanzas contained /\v<(default)>/
"syn keyword confViewStates

" visualizations.conf
syn keyword confVisualizations allow_user_selection default_height search_fragment

" web.conf
syn match   confWebStanzas contained /\v<(settings|endpoint:[^\]]+)>/
syn keyword confWeb startwebserver httpport mgmtHostPort privKeyPath caCertPath
syn keyword confWeb serviceFormPostURL userRegistrationURL updateCheckerBaseURL docsCheckerBaseURL
syn keyword confWeb login_content supportSSLV3Only cipherSuite root_endpoint
syn keyword confWeb template_dir module_dir use_future_expires trustedIP 
syn keyword confWeb js_logger_mode ui_inactivity_timeout js_no_cache
syn keyword confWeb trap_module_exceptions listenOnIPv6 engine.autoreload_on 
syn keyword confWeb jschart_test_mode version_label_format SSOMode rss_endpoint 
syn keyword confWeb enabled_decomposers trustedIP SSOMode request.show_tracebacks
syn keyword confWeb splunkConnectionTimeout pdfgen_is_available auto_refresh_views
syn keyword confWeb x_frame_options_sameorigin response.timeout verifyCookiesWorkDuringLogin
syn keyword confWeb splunkdConnectionTimeout sslVersions allowSsoWithoutChangingServerConf
syn keyword confWeb pivot_adhoc_acceleration_mode jschart_trunctation_limit
syn keyword confWeb override_JSON_MIME_type_with_text_plain customFavicon
syn keyword confWeb dedicatedIoThreads methods pattern skipCSRFProtection oidEnabled export_timeout
syn keyword confWeb jschart_truncation_limit showProductMenu tools.staticdir.generate_indexes
syn keyword confWeb showUserMenuProfile termsOfServiceDirectory dashboard_html_allow_inline_styles
syn keyword confWeb enableWebDebug ssoAuthFailureRedirect allowableTemplatePaths
syn match   confWeb /\v<allowSsl(Compression|Renegotiation)>/
syn match   confWeb /\v<appServer(Ports|ProcessShutdownTimeout)>/
syn match   confWeb /\v<cache(Bytes|Entries)Limit>/
syn match   confWeb /\v<django_((force_)?enable|path)>/
syn match   confWeb /\v<embed_(footer|uri)|login(BackgroundImageOption|CustomBackgroundImage)>/
syn match   confWeb /\v<enable_(autocomplete_login|gzip|insecure_login|pivot_adhoc_acceleration|proxy_write|risky_command_check)>/
syn match   confWeb /\v<enable(SplunkWebSSL|WebDebug)>/
syn match   confWeb /\v<flash_(major|minor|revision)_version>/
syn match   confWeb /\v<job_(max|min)_polling_interval>/
syn match   confWeb /\v<jschart_truncation_limit\.(chrome|firefox|ie[7-9]|ie1[01]|safari)>/
syn match   confWeb /\v<js_logger_mode_server_(end_point|(max|poll)_buffer)>/
syn match   confWeb /\v<log\.access_(file|max(files|size))>/
syn match   confWeb /\v<log\.error_max(files|size)>/
syn match   confWeb /\v<max(Sockets|Threads)>/
syn match   confWeb /\v<max_(upload|view_cache)_size>/
syn match   confWeb /\v<minify_(css|js)>/
syn match   confWeb /\v<productMenu(Label|UriPrefix)>/
syn match   confWeb /\v<remoteUser(MatchExact)?|remoteGroups(Quoted|MatchExact)?>/
syn match   confWeb /\v<server\.(socket_(host|timeout)|thread_pool(_max)?|thread_pool_(max|min)_spare)>/
syn match   confWeb /\v<simple_(error_page|xml_(force_flash_charting|module_render|perf_debug))>/
syn match   confWeb /\v<static(CompressionLevel|_dir|_endpoint)>/
syn match   confWeb /\v<testing_(dir|endpoint)>/
syn match   confWeb /\v<tools\.(decode\.on|encode\.(on|encoding))>/
syn match   confWeb /\v<tools\.proxy\.(base|on)>/
syn match   confWeb /\v<tools\.sessions\.(httponly|on|restart_persist|secure|storage_(path|type)|timeout)>/

syn keyword confWeb_Constants None Firebug Server permissive strict no yes only

" wmi.conf
syn match   confWmiStanzas contained /\v<(settings|WMI:[^\]]+)>/
syn keyword confWmi initial_backoff max_backoff max_retries_at_max_backoff checkpoint_sync_interval
syn keyword confWmi server interval disabled hostname current_only index event_log_file
syn keyword confWmi disable_hostname_normalization wql namespace

" workflow_actions.conf
syn match   confWorkflowActionsStanzas contained /\v<(default)>/
syn keyword confWorkflowActions type label fields eventtypes display_location disabled
syn match   confWorkflowActions /\v<link\.(uri|target|method|postargs\.\d+\.(key|value))>/
syn match   confWorkflowActions /\v<search\.(search_string|app|view|target|earliest|latest|preserve_timerange)>/

"
" splunk_app_db_connect
"

" app-migration.conf
syn keyword confAppMigration STATE DEST_CONF

"
" db_connections.conf
"
syn keyword confDBConnections serviceClass testQuery database connection_type identity isolation_level
syn keyword confDBConnections readonly username password host port informixserver useConnectionPool fetch_size
syn keyword confDBConnections enable_query_wrapping cwallet_location sslConnectionType oracle_cipher_suites
syn match   confDBConnections /\v<max((Idle|Total)Conn|(ConnLifetime|Wait)Millis)>/
syn match   confDBConnections /\v<jdbc(Url(SSL)?Format|UseSSL|DriverClass)>/

"
" db_connection_types.conf
"
syn keyword confDBConnectionTypes serviceClass displayName database port useConnectionPool cwallet_location sslConnectionType oracle_cipher_suites
syn match   confDBConnectionTypes /\v<ui_default_(catalog|schema)>/
syn match   confDBConnectionTypes /\v<supported(Major|Minor)?Version(s)?|jdbc(Url(SSL)?Format|UseSSL|DriverClass)|max((Idle|Total)Conn|(ConnLifetime|Wait)Millis)>/

"
" healthlog.conf
"
syn keyword confHealthlog hiddens loggers

"
" identities.conf
"
syn keyword confIdentities username password domain_name use_win_auth

"
" inputs.conf
"

syn match   confInputsStanzas contained /\v<(mi_output)>/
syn keyword confInputs policy connection key_pattern javahome options port bindIP proc_pid
syn keyword confInputs useSSL keystore_password Exception cert_file cert_validity 
syn keyword confInputs output_timestamp_format resource_pool auto_disable max_retries
syn keyword confInputs user description mode connection query query_timeout max_rows
syn keyword confInputs search is_saved_search time_out transactional customized_mappings
syn match   confInputs /\v<(lookup|update|reload)SQL|(input|output)_fields>/
syn match   confInputs /\v<ui_(query_(mode|catalog|schema|table)|input_((spl|saved)_search)|use_saved_search|is_auto_lookup|query_result_columns|column_output_map|field_column_map|auto_lookup_conditions|mappings|selected_fields|saved_search_str|query_sql)>/
syn match   confInputs /\v<tail_(follow_only|rising_column_(name|number|checkpoint_value))>/
syn match   confInputs /\v<input_timestamp_(format|column_(name|number))>/

syn keyword confInputs_Constants reload update simple advanced

"
" Splunk_TA_f5-bigip
"
syn keyword f5BigIPInputs nothing

"
" Splunk_TA_ibm-was
"
syn keyword IBM_WASInputs was_data_input

"
" ITSI-specific configs
"

" ITSI alert_actions.conf
syn keyword ITSI_AlertActions drilldown_search subtitle delta drilldown_uri invert inline _name
syn match   ITSI_AlertActions /\v<param\.(http_token_name|index|sourcetype|event_identifier_fields|search_type|is_use_event_time|host)>/
syn match   ITSI_AlertActions /\v<param\.(fields|description|protocols|duration|category|limit|verbose)>/
syn match   ITSI_AlertActions /\v<constraint_(method|fields)>/
syn match   ITSI_AlertActions /\v<(value|delta)_qual|group\.\d+\.(name|order)|value(_suffix)?>/
syn match   ITSI_AlertActions /\v<_itsi_(kpi|service)_id>/

" ITSI app_permissions.conf
syn keyword ITSI_App_Permissions capabilities description display_name messages metadata

" ITSI deep_dive_drilldowns.conf
syn keyword ITSI_DeepDiveDrilldowns type replace_tokens search add_lane_enabled use_bucket_timerange new_lane_settings uri uri_payload_type
syn match   ITSI_DeepDiveDrilldowns /\v<entity_(level_only|tokens|activation_rules)>/
syn match   ITSI_DeepDiveDrilldowns /\v<(metric|kpi|event)_lane_enabled>/

" ITSI drawing_elements.conf
syn keyword ITSI_DrawingElements bgColor color stroke height width vizType context_id searchSource threshold_eval use_percentage isThresholdEnabled
syn match   ITSI_DrawingElements /\v<font(Size|Family|Color)>/
syn match   ITSI_DrawingElements /\v<(start|end)PointDecoratorType>/
syn match   ITSI_DrawingElements /\v<label(Val|Flag)>/
syn match   ITSI_DrawingElements /\v<threshold_(field|comparator|values|labels)>/
syn match   ITSI_DrawingElements /\v<dataModel(Specification|StatOp|WhereClause)>/
syn match   ITSI_DrawingElements /\v<gauge_(thresholds|colors)>/
syn match   ITSI_DrawingElements /\v<default(Height|Width)>/
syn match   ITSI_DrawingElements /\v<search_(aggregate|time_series_aggregate|alert_earliest)>/
syn match   ITSI_DrawingElements /\v<use(CustomDrilldown|KpiSearchAlertEarliest)>/

syn keyword ITSI_DrawingElements_Constants none simple triangle

" ITSI drilldownsearch_offset.conf
syn keyword ITSI_DrillDownSearch_Offset timeInSecs
syn match   ITSI_DrillDownSearch_Offset /\v<(earliest_|latest_)?description>/

" ITSI inputs.conf
syn keyword ITSI_Inputs default_severity required_ui_severity suppress debug acceleration manual_rebuilds always_exec group execution_order timeout
syn keyword ITSI_Inputs app_name log_level registered_capabilities import_from_search csv_location search_string selected_services update_type owner
syn match   ITSI_Inputs /\v<app(s_to_update|(_exclude)?_regex|_include_list)>/
syn match   ITSI_Inputs /\v<endpoint(_params)?>/
syn match   ITSI_Inputs /\v<index_(earliest|latest)>/
syn match   ITSI_Inputs /\v<service_(rel|title_field|description_column)>/
syn match   ITSI_Inputs /\v<entity_(title_field|service_columns|identifier_fields|description_column|informational_fields|field_mapping)>/
syn keyword ITSI_Inputs_Constants DEBUG INFO WARN ERROR CRITICAL FATAL

" ITSI itsi_da.conf
syn keyword ITSI_da description saved_search title
syn match   ITSI_da /\v<title(_field)?>/
syn match   ITSI_da /\v<(description|identifier|informational)_fields>/
syn match   ITSI_da /\v<entity_(source_templates|rules)>/
syn match   ITSI_da /\v<(recommended|informational|optional)_kpis>/

" ITSI itsi_deep_dive.conf
syn keyword ITSI_DeepDive focus_id title lane_settings_collection acl mod_time
syn keyword ITSI_DeepDive description is_named _owner source_itsi_da

" ITSI itsi_glass_table.conf
syn keyword ITSI_GlassTable latest earliest title description mod_time acl _owner source_itsi_da
syn match   ITSI_GlassTable /\v<svg_(content|coordinates)>/

" ITSI itsi_kpi_template.conf
syn keyword ITSI_KPI_Template description title _owner kpis source_itsi_da

" ITSI itsi_module_vis.conf
syn keyword ITSI_ModuleVis list control_token title extendable_tab activation_rule
syn match   ITSI_ModuleVis /\v<row\.\d+>/

" ITSI itsi_notable_event_retention.conf
syn keyword ITSI_Notable_Event_Retention retentionTimeInSec disabled

" ITSI itsi_notable_event_severity.conf
syn keyword ITSI_Notable_Event_Severity color lightcolor label default

" ITSI itsi_notable_event_status.conf
syn keyword ITSI_Notable_Event_Status label default description end

" ITSI itsi_service.conf
syn keyword ITSI_Services description title _owner tags kpis entity_rules
syn keyword ITSI_Services identifying_name mod_source source_itsi_da
syn match   ITSI_Services /\v<services_depend(s_on|ing_on_me)>/

" ITSI itsi_settings.conf
syn keyword ITSI_Settings show_migration_message

" ITSI managed_configurations.conf
syn keyword ITSI_Managed_Configurations disabled endpoint label description class link lookup_type
syn match   ITSI_Managed_Configurations /\v<editable(_on_shc)?>/
syn match   ITSI_Managed_Configurations /\v<attribute(_type)?>/
syn match   ITSI_Managed_Configurations /\v<(sav|guid)edsearch>/

" ITSI notable_event_actions.conf
syn keyword ITSI_Notable_Event_Actions disabled

" ITSI postprocess.conf
syn keyword ITSI_PostProcess disabled savedsearch postprocess

" ITSI savedsearches.conf
syn match   ITSI_SavedSearches /\v<display\.page\.\w+\.\d+\.(collection_name|title|color|drilldown_uri|order)>/
syn match   ITSI_SavedSearches /\v<action\.makestreams(\.param\.(fields|description|protocols|duration|category|limit))?>/
syn match   ITSI_SavedSearches /\v<action\.itsi_event_generator(\.param\.(title|description|owner|status|severity))?>/
syn match   ITSI_SavedSearches /\v<action\.itsi_event_generator\.param\.drilldown_search_(title|search|(latest|earliest)_offset)>/
syn match   ITSI_SavedSearches /\v<action\.itsi_event_generator\.param\.(drilldown_(title|uri)|event_identifier_fields|service_ids)>/
syn match   ITSI_SavedSearches /\v<action\.itsi_event_generator\.param\.(entity_lookup_field|search_type|editor)>/
syn match   ITSI_SavedSearches /\v<action\.itsi_event_generator\.param\.(meta_data|is_ad_at|ad_at_kpi_ids)>/
syn match   ITSI_SavedSearches /\v<action\.indicator(\._itsi_(kpi|service)_id)?>/
syn keyword ITSI_SavedSearches action.itsi_sample_event_action_ping.param.host
syn keyword ITSI_SavedSearches action.keyindicator.invert action.makestreams.param.verbose
syn keyword ITSI_SavedSearches_Constants blue red orange yellow purple green

" ITSI service_analyzer_settings.conf
syn keyword ITSI_Service_Analyzer_Settings ftr_override

" ITSI threshold_labels.conf
syn keyword ITSI_Threshold_Labels color lightcolor threshold_level
syn match   ITSI_Threshold_Labels /\v<health_(weight|m(in|ax))>/

" ITSI threshold_periods.conf
syn keyword ITSI_Threshold_Periods past description relative

"
" TA_Azure
"

" inputs.conf
syn keyword AzureInputs storage_account access_key limit pollingInterval
syn keyword AzureInputs site_diagnostics_container subscription_id api_version token_endpoint
syn keyword AzureInputs table_name select_string
syn match   AzureInputs /\v<enableWAD(MetricsPT1(H|M)|(PerformanceCounters|DiagnosticInfrastructureLogs|WindowsEventLogs)Table)>/
syn match   AzureInputs /\v<client_(id|secret)|dateTime(Column|Start)>/

"
" Splunk_TA_jmx
"

" inputs.conf
syn keyword jmxInputs config_file config_file_dir polling_frequency
syn keyword jmxInputs_Constants parsingQueue indexQueue

" Splunk_TA_okta

" alert_actions.conf
syn match   oktaAlertActions /\v<param\.(action|user_(id|name)|group_(id|name))>/

" inputs.conf
syn keyword oktaInputs url token start_date end_date metrics page_size batch_size

" okta.conf
syn keyword oktaOkta loglevel custom_cmd_enabled
syn match   oktaOkta /\v<proxy_(enabled|type|rdns|url|port|username|password)>/
syn match   oktaOkta /\v<okta_server_(url|token)>/

"
" Splunk_TA_oracle
"

" database.conf
syn keyword oracleDatabase database host username password isolation_level port readonly type disabled

" Highlight definitions (generic)
hi def link confComment Comment
hi def link confSpecComment Comment
hi def link confBoolean Boolean
hi def link confTodo Todo

" Other highlights
hi def link confString String
hi def link confNumber Number
hi def link confPath   Number
hi def link confVar    PreProc

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
hi def link confChecklistStanzas Identifier
hi def link confCollectionsStanzas Identifier
hi def link confCommandsStanzas Identifier
hi def link confCrawlStanzas Identifier
hi def link confDataModelsStanzas Identifier
hi def link confDataTypesbnfStanzas Identifier
hi def link confDefmodeStanzas Identifier
hi def link confDeployClientStanzas Identifier
hi def link confDistSearchStanzas Identifier
hi def link confDMCAlertsStanzas Identifier
hi def link confEventDiscoverStanzas Identifier
hi def link confEventGenStanzas Identifier
hi def link confEventRenderStanzas Identifier
hi def link confEventTypesStanzas Identifier
hi def link confFieldsStanzas Identifier
hi def link confIndexesStanzas Identifier
hi def link confInputsStanzas Identifier
hi def link confInstanceStanzas Identifier
hi def link confLimitsStanzas Identifier
hi def link confLivetailStanzas Identifier
hi def link confLauncherStanzas Identifier
hi def link confSALDAPStanzas Identifier
hi def link confSALDAPSSLStanzas Identifier
hi def link confSALDAPLoggingStanzas Identifier
hi def link confMetaStanzas Identifier
hi def link confOutputsStanzas Identifier
hi def link confPasswordsStanzas Identifier
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
hi def link confMCAssetsStanzas Identifier
hi def link confTenantsStanzas Identifier
hi def link confTimesStanzas Identifier
hi def link confTransactionTypesStanzas Identifier
hi def link confTransformsStanzas Identifier
hi def link confUIPrefsStanzas Identifier
hi def link confUIToursStanzas Identifier
hi def link confUserPrefsStanzas Identifier
hi def link confUserSeedStanzas Identifier
hi def link confViewStatesStanzas Identifier
hi def link confWebStanzas Identifier
hi def link confWmiStanzas Identifier
hi def link confWorkflowActionsStanzas Identifier
hi def link confSearchbnfStanzas Identifier

" Highlight definitions (by .conf)
hi def link confADmon Keyword
hi def link confAlertActions Keyword
hi def link confAlertActions_Constants Constant
hi def link confApp Keyword
hi def link confApp_Constants Constant
hi def link confAudit Keyword
hi def link confAuthentication Keyword
hi def link confAuthentication_Constants Constant
hi def link confAuthorize Keyword
hi def link confAuthorizeCaps Underlined
hi def link confChecklist Keyword
hi def link confCollections Keyword
hi def link confCollections_Constants Constant
hi def link confCommands Keyword
hi def link confCommands_Constants Constant
hi def link confCrawl Keyword
hi def link confDataTypesbnf Keyword
hi def link confDataModels Keyword
hi def link confDataModelsConstants Constant
hi def link confDefmode Keyword
hi def link confDeployClient Keyword
hi def link confDeployClient_Constants Constant
hi def link confDistSearch Keyword
hi def link confDMCAlerts Keyword
hi def link confEventRender Keyword
hi def link confEventDiscover Keyword
hi def link confEventGen Keyword
hi def link confEventTypes Keyword
hi def link confFields Keyword
hi def link confIndexes Keyword
hi def link confIndexes_Constants Constant
hi def link confInputs Keyword
hi def link confInputs_Constants Constant
hi def link confInstance Keyword
hi def link confLauncher Keyword
hi def link confSALDAP Keyword
hi def link confSALDAPLogging Keyword
hi def link confSALDAPLogging_Constants Constant
hi def link confSALDAPSSL Keyword
hi def link confLimits Keyword
hi def link confLimits_Constants Constant
hi def link confLivetail Keyword
hi def link confLivetail_Constants Constant
hi def link confMeta Keyword
hi def link confMeta_Constants Constant
hi def link confMacros Keyword
hi def link confMessages Keyword
hi def link confMessagesConstants Constant
hi def link confMultikv Keyword
hi def link confOutputs Keyword
hi def link confOutputs_Constants Constant
hi def link confPasswords Keyword
hi def link confPDFserver Keyword
hi def link confProcmonFilters Keyword
hi def link confProps Keyword
hi def link confProps_Constants Constant
hi def link confComplex Preproc
hi def link confPubsub Keyword
hi def link confPubsub_Constants Constant
hi def link confRegmonFilters Keyword
hi def link confRestmap Keyword
hi def link confSavedSearches Keyword
hi def link confSavedSearches_Constants Constant
hi def link confSearchbnf Keyword
hi def link confSearchbnf_Constants Constant
hi def link confSegmenters Keyword
hi def link confServer Keyword
hi def link confServer_Constants Constant
hi def link confServerClass Keyword
hi def link confSourceClass Keyword
hi def link confSourceTypes Keyword
hi def link confSplunkLaunch Keyword
hi def link confMCAssets Keyword
hi def link confTags Keyword
hi def link confTelemetry Keyword
hi def link confTenants Keyword
hi def link confTimes Keyword
hi def link confTransactionTypes Keyword
hi def link confTransforms Keyword
hi def link confTransforms_Constants Constant
hi def link confUIPrefs Keyword
hi def link confUIPrefs_Constants Constant
hi def link confUITour Keyword
hi def link confUITour_Constants Constant
hi def link confUserPrefs Keyword
hi def link confUserSeed Keyword
hi def link confViewStates Keyword
hi def link confVisualizations Keyword
hi def link confWeb Keyword
hi def link confWeb_Constants Constant
hi def link confWmi Keyword
hi def link confWorkflowActions Keyword

" splunk_app_db_connect
hi def link confAppMigration Keyword
hi def link confDBConnections Keyword
hi def link confDBConnectionTypes Keyword
hi def link confHealthlog Keyword
hi def link confIdentities Keyword

" TA_Azure
hi def link AzureInputs Keyword

" Splunk_TA_f5
hi def link f5BigIPInputs Keyword

" Splunk_TA_ibm-was
hi def link IBM_WASInputs Keyword

" ITSI
hi def link ITSI_AlertActions Keyword
hi def link ITSI_App_Permissions Keyword
hi def link ITSI_DeepDiveDrilldowns Keyword
hi def link ITSI_DrawingElements Keyword
hi def link ITSI_DrawingElements_Constants Constant
hi def link ITSI_DrillDownSearch_Offset Keyword
hi def link ITSI_Inputs Keyword
hi def link ITSI_Inputs_Constants Constant
hi def link ITSI_da Keyword
hi def link ITSI_DeepDive Keyword
hi def link ITSI_GlassTable Keyword
hi def link ITSI_KPI_Template Keyword
hi def link ITSI_ModuleVis Keyword
hi def link ITSI_Notable_Event_Retention Keyword
hi def link ITSI_Notable_Event_Severity Keyword
hi def link ITSI_Notable_Event_Status Keyword
hi def link ITSI_Services Keyword
hi def link ITSI_Settings Keyword
hi def link ITSI_Managed_Configurations Keyword
hi def link ITSI_Notable_Event_Actions Keyword
hi def link ITSI_PostProcess Keyword
hi def link ITSI_SavedSearches Keyword
hi def link ITSI_SavedSearches_Constants Constant
hi def link ITSI_Service_Analyzer_Settings Keyword
hi def link ITSI_Threshold_Labels Keyword
hi def link ITSI_Threshold_Periods Keyword

" JMX Add-on
hi def link jmxInputs Keyword
hi def link jmxInputs_Constants Constant

" Splunk_TA_okta
hi def link oktaAlertActions Keyword
hi def link oktaInputs Keyword
hi def link oktaOkta Keyword

" Splunk_TA_oracle
hi def link oracleDatabase Keyword
