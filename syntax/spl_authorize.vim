" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" authorize.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confAuthorizeStanzas,confDeprecatedStanzas,,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(accelerate_(datamodel|search)|admin_all_objects|change_(authentication|own_password)))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(delete_by_keyword|dispatch_rest_to_indexers|get_(diag|metadata|typeahead)))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(run_multi_phased_searches|never_(lockout|expire)))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)edit_(deployment_(client|server)|dist_peer|encryption_key_provider|forwarders|httpauths))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)edit_(indexer(_cluster|discovery)|input_defaults|monitor|kvstore))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)edit_(modinput_(win(host|net|print)mon|(perf|ad)mon)|roles(_grantable)?))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)edit_(scripted|search_(head_clustering|scheduler|server)|search_schedule_(priority|window)))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)edit_(server(_crl)?|sourcetypes|splunktcp(_ssl|_token)?|tcp|telemetry_settings|token_http))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)edit_(udp|user|view_html|web_settings))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(export_results_is_visible|indexes_edit|input_file|license_(edit|read|view_warnings)|web_debug))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)list_(deployment_(client|server)|forwarders|httpauths|indexer(_cluster|discovery)|inputs|health|metrics_catalog))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)list_(introspection|search_(head_clustering|scheduler)|settings|storage_passwords))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(output_file|request_remote_tok|rest_(apps_(management|view)|properties_(g|s)et)|restart_splunkd))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(rtsearch|run_debug_commands|schedule_(rt)?search|search(_process_config_refresh)?|extra_x509_validation))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(request_pstacks|edit_health|run_(m)?collect))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(edit_(statsd_transforms|metric_schema)|(edit|list|select)_workload_pools|(list|edit)_workload_rules))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)edit_(tokens_(all|own|settings)|watchdog|local_apps))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)edit_(search_concurrency_(all|scheduled)|metrics_rollup))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)list_(pipeline_sets|tokens_(all|own|scs)))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(upload_lookup_files|apps_restore|fsh_(search|manage)))>/
syn match   confAuthorizeStanzas contained /\v<(tokens_auth)>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(delete_messages|edit_(authentication_extensions|bookmarks_mc)|list_dist_peer|install_apps|metric_alerts))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)edit_(log_alert_event|health_subset))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(list_(health_subset|token_http)|pattern_detect|run_(msearch|walklex)))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)((list|edit)_workload_policy|edit_global_banner))>/
syn match   confAuthorizeStanzas contained /\v<(commands:user_configurable|capability::edit_manager_xml)>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)list_accelerate_search)>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)((edit_own|list_all)_objects|(edit|list)_ingest_rulesets|edit_modinput_journald))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)run_(dump|custom_command|sendalert|commands_ignoring_field_filter)|rest_access_server_endpoints)>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(rest_access_server_endpoints|upload_mmdb_files|edit_field_filter))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(list_(cascading_plans|remote_(input|output)_queue)))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(merge_buckets|edit_web_features|read_internal_libraries_settings))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(change_(audit|user_seed)|edit_(storage_passwords|cmd|upload_and_index|tcp_stream|restmap)|restart_reason|embed_report|refresh_application_licenses))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(apps_backup|use_remote_proxy|capture_ingest_events))>/
syn match   confAuthorizeStanzas contained /\v<(role_(admin|user|can_delete|power|splunk-system-role))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(list_all_(users|roles)|edit_(messages|user_seed)))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)((create|edit)_external_lookup|list_field_filter|edit_spl2_permissions))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)((edit|list)_certificates|edit_saved_search(_owner)?|list_saved_searches))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(edit_published_dashboards|(list|edit)_spl2_modules|edit_spl2_datasets))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(run_spl2_search|(edit|provision)_data_management_agent|edit_data_management_edgeprocessor))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)((list|edit)_data_management_otelcollector|delete_saml_user))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(list|edit)_alert_actions)>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)((list|edit)(_spl2_module_permissions|(auto_refresh|deactivate)_dashboards)))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)edit_data_management_pipeline_job)>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)((list_|edit_)(oauth_config(s|_role_mappings)|internal_oauth_clients|authentication_node)))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)((delete|list)_oauth_config_clients))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(edit|read)_connections)>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(edit|read|write)_datasets)>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)edit_(storage_passwords_masking|heap_profiler))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(create_bulk_data_move|(auto_refresh|deactivate)_dashboards))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)edit_((out|in)put_ingest_processor|federated_indexes))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(list_|edit_)(federated_providers|conf_objects))>/

" Capabilities
syn match   confAuthorizeCaps /\v<^((accelerate_(datamodel|search)|admin_all_objects|change_(authentication|own_password)))>/
syn match   confAuthorizeCaps /\v<^((delete_by_keyword|dispatch_rest_to_indexers|get_(diag|metadata|typeahead)))>/
syn match   confAuthorizeCaps /\v<^(edit_(deployment_(client|server)|dist_peer|encryption_key_provider|forwarders|httpauths))>/
syn match   confAuthorizeCaps /\v<^(edit_(indexer(_cluster|discovery)|input_defaults|monitor))>/
syn match   confAuthorizeCaps /\v<^(edit_(modinput_(win(host|net|print)mon|(perf|ad)mon)|roles(_grantable)?))>/
syn match   confAuthorizeCaps /\v<^(edit_(scripted|search_(head_clustering|scheduler|server)|search_schedule_(priority|window)))>/
syn match   confAuthorizeCaps /\v<^(edit_(server(_crl)?|sourcetypes|splunktcp(_ssl|_token)?|tcp|telemetry_settings|token_http))>/
syn match   confAuthorizeCaps /\v<^(edit_(udp|user|view_html|web_settings))>/
syn match   confAuthorizeCaps /\v<^((export_results_is_visible|indexes_edit|input_file|license_(edit|read|view_warnings)|web_debug))>/
syn match   confAuthorizeCaps /\v<^(list_(deployment_(client|server)|forwarders|httpauths|indexer(_cluster|discovery)|inputs))>/
syn match   confAuthorizeCaps /\v<^(list_(introspection|search_(head_clustering|scheduler)|settings|storage_passwords))>/
syn match   confAuthorizeCaps /\v<^((output_file|request_remote_tok|rest_(apps_(management|view)|properties_(g|s)et)|restart_splunkd))>/
syn match   confAuthorizeCaps /\v<^((rtsearch|run_debug_commands|schedule_(rt)?search|search(_process_config_refresh)?))>/
syn match   confAuthorizeCaps /\v<^(edit_(tokens_(all|own|settings)|watchdog|local_apps))>/
syn match   confAuthorizeCaps /\v<^(edit_(search_concurrency_(all|scheduled)|metrics_rollup))>/
syn match   confAuthorizeCaps /\v<^(list_(pipeline_sets|tokens_(all|own|scs)))>/
syn match   confAuthorizeCaps /\v<^((upload_lookup_files|apps_restore|fsh_(search|manage)))>/
syn match   confAuthorizeCaps /\v<^(edit_(authentication_extensions|bookmarks_mc)|list_dist_peer|install_apps|metric_alerts)>/
syn match   confAuthorizeCaps /\v<^(delete_messages|edit_(log_alert_event|health(_subset)?)|request_pstacks)>/
syn match   confAuthorizeCaps /\v<^(list_(accelerate_search|health(_subset)?|metrics_catalog|token_http))>/
syn match   confAuthorizeCaps /\v<^(never_(lockout|expire)|pattern_detect|run_(collect|m(collect|search)|walklex))>/
syn match   confAuthorizeCaps /\v<^(edit_(global_banner|kvstore|manager_xml|metric_schema|statsd_transforms|workload_(pools|rules|policy)))>/
syn match   confAuthorizeCaps /\v<^(select_workload_pools|list_(workload_(pools|rules|policy)))>/
syn match   confAuthorizeCaps /\v<^((edit_own|list_all)_objects|run_(dump|sendalert|custom_command)|rest_access_server_endpoints|embed_report)>/
syn match   confAuthorizeCaps /\v<^(run_commands_ignoring_field_filter|change_audit|edit_(cmd|upload_and_index|tcp_stream|field_filter|restmap))>/
syn match   confAuthorizeCaps /\v<^(refresh_application_licenses|restart_reason|edit_storage_passwords|apps_backup|list_(cascading_plans|remote_(input|output)_queue)|(list|edit)_ingest_rulesets|capture_ingest_events)>/
syn match   confAuthorizeCaps /\v<^(read_internal_libraries_settings|edit_web_features|upload_mmdb_files|use_remote_proxy|merge_buckets)>/
syn match   confAuthorizeCaps /\v<^(list_all_(users|roles)|list_field_filter|(create|edit)_external_lookup|edit_spl2_permissions)>/
" Enterprise Security
syn match   confAuthorizeCaps /\v<^(edit_(correlationsearches|identitylookup|log_review_settings|lookups|managed_configurations|suppressions))>/

" Key words
syn match   confAuthorize /\v<^(federatedProviders|expiration|ephemeralExpiration)>/
syn match   confAuthorize /\v<^(srch(Filter(Selecting)?|Time(Win|Earliest)|(Disk|Jobs)Quota|MaxTime|Indexes(Default|Allowed|Disallowed)))>/
syn match   confAuthorize /\v<^(rtSrchJobsQuota|(import|grantable)Roles|deleteIndexesAllowed|cumulative(Srch|RTSrch)JobsQuota)>/
syn match   confAuthorize /\v<^(fieldFilter(Limit|Exemption)|prefix)>/
syn match   confAuthorize /\v<^(kvstore_(create|update|delete)\.(implicit_)?deny_list)>/
syn match   confAuthorize /\v<^(srchFederatedProviders(Allowed|Default)|queuedSearchQuota)>/

" Constants
syn match   confAuthorizeConstants /\v<(never)$>/

" Complex keys
syn match   confAuthorizeComplex /\v<^(fieldFilter-\k+)>/
syn match   confAuthorizeComplex /\v<((host|source(type)?)::\k+)$>/

" Deprecated
syn match   confDeprecatedStanzas contained /\v<((role_|capability::)(license_tab|use_file_operator))>/
syn match   confDeprecated /\v<(license_tab|use_file_operator)>/

" Highlighting
hi def link confAuthorizeStanzas Identifier
hi def link confAuthorize Keyword
hi def link confAuthorizeCaps Type
hi def link confAuthorizeConstants Constant
hi def link confAuthorizeComplex PreProc
hi def link confDeprecatedStanzas Removed
hi def link confDeprecated Removed
