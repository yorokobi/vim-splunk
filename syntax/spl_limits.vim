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
syn cluster confStanzas contains=confLimitsStanzas,confGenericStanzas

" limits.conf
syn match   confLimitsStanzas contained /\v<(default|anomalousvalue|associate|authtokens|auto(_summarizer|regress)|concurrency|correlate|ctable)>/
syn match   confLimitsStanzas contained /\v<(discretize|ex(port|tern)|findkeywords|geo(mfilter|stats)|http_input|indexpreview|input(_channels|csv|proc))>/
syn match   confLimitsStanzas contained /\v<(iplocation|join|journal_compression|kmeans|kv(store)?|ldap|lookup|metadata|metrics(:tcpin_connections)?)>/
syn match   confLimitsStanzas contained /\v<(mv(combine|expand)|outputlookup|parallelreduce|pdf|rare|realtime|restapi|reversedns|rex|sample|scheduler)>/
syn match   confLimitsStanzas contained /\v<(search(_(info|metrics|optimization(::(eval_merge|merge_union|predicate_(merge|push|split)|projection_eliminate))?))?)>/
syn match   confLimitsStanzas contained /\v<(search_optimization::(projection_elimination|replace_append_with_union|required_field_values|search_(flip|sort)_normalization))>/
syn match   confLimitsStanzas contained /\v<(searchresults|set|show_source|slc|slow_peer_disconnect|sort|spath|(si|t)?stats|subsearch|summarize|system_checks|thruput)>/
syn match   confLimitsStanzas contained /\v<(top|transactions|tscollect|type(ahead|r)|viewstates|xyseries)>/

" --------------
"  Splunk 7.1
" --------------
syn match   confLimitsStanzas  contained /\v<(scheduled_views|search_optimization::search_expansion|directives)>/

syn match   confLimits /\v<^(DelayArchiveProcessorShutdown|action(_execution_threads|s_queue_(size|timeout))|add(_offset|_timestamp|peer_skew_limit))>/
syn match   confLimits /\v<^(aggregate_metrics|alert(ing_period_ms|s_(expire_period|max_(count|history)|scoping)))>/
syn match   confLimits /\v<^(allow_(batch_mode|event_summarization|inexact_metasearch|multiple_matching_users|old_summaries|reuse))>/
syn match   confLimits /\v<^(apply_search_filter|approx_dc_threshold|auto_cancel_after_pause|auto_summary_perc(\.\d+(\.when)?)?|avg_extractor_time)>/
syn match   confLimits /\v<^(base_max_searches|batch_(index_query|response_limit|retry_((min|max)_interval|scaling)|wait_after_end))>/
syn match   confLimits /\v<^(batch_search_(activation_fraction|max_(index_values|pipeline|(results_aggregator|serialized_results)_queue_size)))>/
syn match   confLimits /\v<^(blocking|bound_on_disconnect_threshold_as_fraction_of_mean|cache_(timeout|ttl(_sec)?))>/
syn match   confLimits /\v<^(bucket_localize_(max_(lookahead|timeout_sec)|status_check_period_ms)|bucket_(predictor|refresh_interval(_cluster)?))>/
syn match   confLimits /\v<^(check_splunkd_period|chunk_(multiplier|size)|cmds_black_list|compression_level|concurrency_message_throttle_time)>/
syn match   confLimits /\v<^(db_path|dc_digest_bits|debug_metrics|default_(allow_queue|backfill|partitions|save_ttl|time_bins)|detailed_dashboard)>/
syn match   confLimits /\v<^((en|dis)abled|disk_usage_update_period|dispatch_(dir_warning_size|quota_(retry|sleep_ms)|retry_delay)|distributed(_search_limit)?)>/
syn match   confLimits /\v<^(do_not_use_summaries|enable_(clipping|cumulative_quota|datamodel_meval|generalization|history|memory_tracker|reaper|status_cache))>/
syn match   confLimits /\v<^(enforce_time_order|expiration_time|extract(_all|ion_cutoff)|failed_job_ttl|fetch_(multiplier|remote_search_log))>/
syn match   confLimits /\v<^(fields(_black_list|tats_update_(freq|maxperiod))?|file_tracking_db_threshold_mb|filter(edindexes_log_level|strategy))>/
syn match   confLimits /\v<^(force_saved_search_dispatch_as_user|grace_period_before_disconnect|hot_bucket_min_new_events)>/
syn match   confLimits /\v<^(idle_process_(cache_(search_count|timeout)|reaper_period|regex_cache_hiwater)|introspection_lookback)>/
syn match   confLimits /\v<^(inactive_eligibility_age_seconds|indexed_as_exact_metasearch|index(filter|time_lag)|jobscontentmaxcount)>/
syn match   confLimits /\v<^(indexed_realtime_((cluster_)?update_interval|(default|maximum)_span|disk_sync_delay|use_by_default))>/
syn match   confLimits /\v<^(infocsv_log_level|inputlookup_merge|installed_files_integrity|insufficient_search_capabilities|interval)>/
syn match   confLimits /\v<^(keepresults|launcher_(max_idle_checks|threads)|learned_sourcetypes_limit|limit|list_maxsize|load_remote_bundles)>/
syn match   confLimits /\v<^(local_(connect|receive|send)_timeout|long_search_threshold|lowater_inactive|maintenance_period|match_limit)>/
syn match   confLimits /\v<^(max(KBps|ReducersPerPhase|RunningPrdSearches|_accelerations_per_collection|_action_results|_blocking_secs|_bucket_bytes))>/
syn match   confLimits /\v<^(max_(chunk_queue_size|combiner_memevents|concurrent_per_user|content_length|continuous_scheduled_search_lookback|count))>/
syn match   confLimits /\v<^(max_(documents_per_batch_save|events_per_bucket|extractor_time|fd|fields_per_acceleration|(history|id)_length))>/
syn match   confLimits /\v<^(max_(inactive|infocsv_messages|lock_file(s|_ttl)?|lookup_messages|macro_depth|matches|hot_bucket_summarization_idle_time))>/
syn match   confLimits /\v<^(max_(mem(_usage_mb|table_bytes)|number_of_(ack(_channel|ed_requests_pending_query(_per_ack_channel)?)|tokens)))>/
syn match   confLimits /\v<^(max_((old_bundle|replicated_hot_bucket)_idle_time|per_result_alerts(_time)?|preview_(bytes|period)|queries_per_batch))>/
syn match   confLimits /\v<^(max_((rawsize|results)_perchunk|reverse_matches|rows_(in_memory_per_dump|per_(query|table))))>/
syn match   confLimits /\v<^(max_(rt_search_multiplier|run_stats|searches_(per_(cpu|process)|perc(\.\d(\.when)?)?)))>/
syn match   confLimits /\v<^(max_(size_per_((batch_(result|save)|result)_mb)|stream_window|subsearch_depth|summary_(ratio|size)))>/
syn match   confLimits /\v<^(max_(threads_per_outputlookup|time(_per_process|after|before)?|tolerable_skew|users_to_precache|valuemap_bytes))>/
syn match   confLimits /\v<^(max_(verify_(bucket(_time|s)|ratio|total_time)|workers_searchparser))>/
syn match   confLimits /\v<^(max(bins|chars|clusters|cols|count|datapoints|events|fields|files|k(range|value)|len|mem_check_freq|open(events|txn)|out|p|range))>/
syn match   confLimits /\v<^(max(resultrows|samples|series|time|totalsamples|values(ize)?|zoomlevel)|merge_to_base_search|metrics_report_interval)>/
syn match   confLimits /\v<^(min_(batch_size_bytes|freq|prefix_len(gth)?|preview_period|results_perchunk)|mkdir_max_retries|monitornohandle_max_heap_mb)>/
syn match   confLimits /\v<^(natural_sort_output|normalized_summaries|optimize_max_size_mb|orphan_searches|outputlookup_check_permission|packets_per_data_point)>/
syn match   confLimits /\v<^(partitions_limit|perc_(digest_type|method)|perf_warn_limit|persistance_period|phased_execution|poll_buckets_until_maxtime)>/
syn match   confLimits /\v<^((preview|reduce)_(duty_cycle|freq)|priority_(runtime|skipped)_factor|process_(max_age|min_age_before_user_change)|queue(_size|d_job_check_freq))>/
syn match   confLimits /\v<^(rdigest_(k|maxnodes)|rdnsMaxDutyCycle|realtime_buffer|reaper_(freq|soft_warn_level)|reducers|regex_cpu_profiling)>/
syn match   confLimits /\v<^(remote_(event_download_(finalize|initialize|local)_pool|reduce_limit|ttl))>/
syn match   confLimits /\v<^(remote_timeline(_(connection_timeout|fetchall|max_(count|size_mb)|min_peers|parallel_fetch|prefetch|(receive|send)_timeout|thread|touchperiod))?)>/
syn match   confLimits /\v<^(render_endpoint_timeout|replication_(file_ttl|period_sec)|result(_queue_max_size|s_queue_min_size)|return_actions_with_normalized_ids)>/
syn match   confLimits /\v<^(reuse_map_maxsize|rr_(m(ax|in)_sleep_ms|sleep_factor)|saved_searches_disabled|scheduled_view_timeout|sensitivity)>/
syn match   confLimits /\v<^(search_((2_hash_cache|history_load)_timeout|history_max_runtimes|keepalive_(frequency|max)|process_(memory_usage_(percentage_)?threshold|mode)))>/
syn match   confLimits /\v<^(shc_(accurate_access_counts|local_quota_check|(role|syswide)_quota_enforcement)|show_warn_on_filtered_indexes|shp_dispatch_to_slave)>/
syn match   confLimits /\v<^(sleep_seconds|soft_preview_queue_size|sparkline_(maxsize|time_steps)|squashcase|stack_size|stale_lock_seconds)>/
syn match   confLimits /\v<^(status_(buckets|cache_(in_memory_ttl|size)|period_ms)|subsearch_(max(out|time)|timeout)|summariesonly|summary_mode)>/
syn match   confLimits /\v<^(suppress_derived_info|sync_bundle_replication|tailing_proc_speed|target_time_perchunk|tdigest_(k|max_buffer_size))>/
syn match   confLimits /\v<^(threads|threshold_(connection_life_time|data_volume)|time(_before_close|_format_reject|line_(events_preview|freq)))>/
syn match   confLimits /\v<^(tocsv_(maxretry|retryperiod_ms)|track_indextime_range|truncate_report|ttl|unified_search|use_(bloomfilter|cache|directives|dispatchtmp_dir|metadata_elimination))>/
syn match   confLimits /\v<^(verify_delete|warn_on_missing_summaries|winningRate|write_multifile_results_out|zl_0_gridcell_(lat|long)span)>/

" --------------
"  Splunk 7.1
" --------------
syn match   confLimits /\v<^(results_queue_read_timeout_sec|search_retry|phased_execution_mode|depth_limit)>/
syn match   confLimits /\v<^(check_search_marker_(done|sleep)_interval|monitornohandle_max_driver_(mem_mb|records))>/
syn match   confLimits /\v<^(required_(tags|eventtypes)|read_summary|maxPrdSearchesPerCpu)>/

" 7.2.3
syn match   confLimits /\v<^(results_(serial_format|compression_algorithm)|always_include_indexedfield_lispy)>/
syn match   confLimits /\v<^(bucket_localize_(acquire_lock_timeout_sec|lookahead_priority_ratio)|srtemp_dir_ttl)>/

syn match   confLimitsConstants /\v<(host|splunk_server|all|consec_not_needed|everything|enabled|disabled(SavedSearches)?|DEBUG|INFO|WARN|ERROR|csv|srs|gzip|zstd)$>/
syn match   confLimitsConstants /\v<(log_only|(r|t)digest|nearest-rank|interpolated|yes|no|fromcontext|auto|traditional|debug\s+\S+\s+\S+|only|none)$>/

" --------------
"  Splunk 7.1
" --------------
syn match   confLimitsConstants /\v<((single|multi)threaded)$>/

" 7.3.0
syn match   confLimitsStanzas  contained /\v<(search_optimization::(dfs_job_extractor|reverse_calculated_fields|replace_(table_with_fields|stats_cmds_with_tstats)))>/
syn match   confLimitsStanzas  contained /\v<(rollup|dfs)>/

syn match   confLimits /\v<^(file_and_directory_eliminator_reaper_interval|enable_conditional_expansion|record_search_telemetry)>/
syn match   confLimits /\v<^(max_(searchinfo_map_size|audit_sourcetypes)|track_matching_sourcetypes|execute_postprocess_in_search)>/
syn match   confLimits /\v<^(bucket_localize_status_check_backoff_start_ms|indexed_csv_(ttl|keep_alive_timeout|inprogress_max_timeout))>/
syn match   confLimits /\v<^(indexed_kv_limit|persistence_period|commands|minSpanAllowed)>/
syn match   confLimits /\v<^(dfc_(control_port|num_slots)|dfs_max_(num_keepalives|reduce_partition_size))>/
syn match   confLimits /\v<^(dfw_(num_(slots(_enabled)?)|receiving_data_port(_count)?))>/

" 8.1.0
syn match   confLimitsStanzas contained /\v<(metric_alerts|msearch|(si|m)stats|auth|kvstore_migration|mcollect|segmenter)>/
syn match   confLimitsStanzas contained /\v<(search_optimization::(replace_datamodel_stats_cmds_with_tstats|pr_job_extractor))>/

syn match   confLimits /\v<^((agg|m(s)?p|(c)?lb)_cpu_profiling|subsearch_artifacts_delete_policy|bundle_status_expiry_time|search_telemetry_file_limit)>/
syn match   confLimits /\v<^(indexed_fields_expansion|use_search_evaluator_v2|bucket_localize_connect_timeout_max_retries|read_final_results_from_timeliner)>/
syn match   confLimits /\v<^(search_process_(configure_oom_score_adj|set_oom_score_adj)|log_search_messages|search_messages_severity)>/
syn match   confLimits /\v<^(ingest_(max_memtable_bytes|lookup_refresh_period_secs)|shared_provider_cache_size|input_errors_fatal)>/
syn match   confLimits /\v<^(condition_evaluation_interval|search_(delay|ttl)|honor_action|target_per_timeseries|create_context|tmpfile_compression(_level)?)>/
syn match   confLimits /\v<^(time_bin_limit|enable_install_apps|periodic_timer_interval|max_failed_status_unchanged_count|restprocessor_errors_fatal)>/
syn match   confLimits /\v<^(tscollect_queue_size|commands_(add|rm)|autoAppliedPercentage|rdinPairingTimeout|always_use_single_value_output)>/
syn match   confLimits /\v<^(dfs_(max_search_result_size|resource_awareness|post_proc_speedup|num_post_proc_speedup_threads|post_proc_(in|out)put_queue_size|estimation_time))>/
syn match   confLimits /\v<^(dfs_(remote_search_timeout|max_remote_pipeline|meta_phase_exec_timeout|enable_parallel_serializer|num_of_remote_serializer_pipeline|remote_io_kickout_period|eventcount_limit))>/
syn match   confLimits /\v<^(enable_dfs_search_f(eed|all)back|use_segmenter_v2)>/

syn match   confLimitsConstants /\v<(immediate|ttl|app|user|system)$>/

" 8.2
syn match   confLimitsStanzas contained /\v<(dbinspect|search_optimization::set_required_fields)>/

syn match   confLimits /\v<^(get_summary_id_(connection|rcv|send)_timeout|max_id_length_before_hash|max_fieldmeta_cnt_ui)>/
syn match   confLimits /\v<^(enable_splunkd_kv_lookup_indexing|enforce_auto_lookup_order|max_keymap_rows|use_(spill_thread|stats_v2))>/
syn match   confLimits /\v<^(async_saved_search_(fetch|interval)|defaultReducersPerPhase)>/
syn match   confLimits /\v<^(autoAppliedToAdhocSearches|maxPreviewMemUsageMb|enablePreview|disabledCommandList|detect_search_time_field_collisions|stats)>/
syn match   confLimits /\v<^(max_searches_started_per_cycle|include_events_omitted_when_filtering_numeric_values)>/

syn match   confLimitsConstants /\v<(fixed-width)$>/

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
hi def link confLimitsStanzas Identifier
hi def link confLimits Keyword
hi def link confLimitsConstants Constant
