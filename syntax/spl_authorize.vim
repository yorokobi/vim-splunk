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
syn cluster confStanzas contains=confAuthorizeStanzas,confGenericStanzas

" authorize.conf
syn match   confAuthorizeStanzas contained /\v<(default)>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(accelerate_(datamodel|search)|admin_all_objects|change_(authentication|own_password)))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(delete_by_keyword|dispatch_rest_to_indexers|get_(diag|metadata|typeahead)))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(run_multi_phased_searches|never_(lockout|expire)))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)edit_(deployment_(client|server)|dist_peer|encryption_key_provider|forwarders|httpauths))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)edit_(indexer(_cluster|discovery)|input_defaults|monitor|kvstore))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)edit_(modinput_(win(host|net|print)mon|(perf|ad)mon)|roles(_grantable)?))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)edit_(scripted|search_(head_clustering|scheduler|server)|search_schedule_(priority|window)))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)edit_(server(_crl)?|sourcetypes|splunktcp(_ssl|_token)?|tcp|telemetry_settings|token_http))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)edit_(udp|user|view_html|web_settings))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(export_results_is_visible|indexes_edit|input_file|license_(tab|edit|read|view_warnings)|web_debug))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)list_(deployment_(client|server)|forwarders|httpauths|indexer(_cluster|discovery)|inputs|health|metrics_catalog))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)list_(introspection|search_(head_clustering|scheduler)|settings|storage_passwords))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(output_file|request_remote_tok|rest_(apps_(management|view)|properties_(g|s)et)|restart_splunkd))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(rtsearch|run_debug_commands|schedule_(rt)?search|search(_process_config_refresh)?|use_file_operator|extra_x509_validation))>/

" 7.2.3
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(request_pstacks|edit_health|run_(m)?collect))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(edit_(statsd_transforms|metric_schema)|(edit|list|select)_workload_pools|(list|edit)_workload_rules))>/

syn match   confAuthorize /\v<^(srch(Filter(Selecting)?|Time(Win|Earliest)|(Disk|Jobs)Quota|MaxTime|Indexes(Default|Allowed|Disallowed)))>/
syn match   confAuthorize /\v<^(rtSrchJobsQuota|(import|grantable)Roles|deleteIndexesAllowed|cumulative(Srch|RTSrch)JobsQuota)>/
" 7.3.0
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)edit_(tokens_(all|own|settings)|watchdog|local_apps))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)edit_(search_concurrency_(all|scheduled)|metrics_rollup))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)list_(pipeline_sets|tokens_(all|own|scs)))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(upload_lookup_files|apps_restore|fsh_(search|manage)))>/
syn match   confAuthorize /\v<^(federatedProviders|expiration|disabled|ephemeralExpiration)>/

syn match   confAuthorizeCaps /\v<^((accelerate_(datamodel|search)|admin_all_objects|change_(authentication|own_password)))>/
syn match   confAuthorizeCaps /\v<^((delete_by_keyword|dispatch_rest_to_indexers|get_(diag|metadata|typeahead)))>/
syn match   confAuthorizeCaps /\v<^(edit_(deployment_(client|server)|dist_peer|encryption_key_provider|forwarders|httpauths))>/
syn match   confAuthorizeCaps /\v<^(edit_(indexer(_cluster|discovery)|input_defaults|monitor))>/
syn match   confAuthorizeCaps /\v<^(edit_(modinput_(win(host|net|print)mon|(perf|ad)mon)|roles(_grantable)?))>/
syn match   confAuthorizeCaps /\v<^(edit_(scripted|search_(head_clustering|scheduler|server)|search_schedule_(priority|window)))>/
syn match   confAuthorizeCaps /\v<^(edit_(server(_crl)?|sourcetypes|splunktcp(_ssl|_token)?|tcp|telemetry_settings|token_http))>/
syn match   confAuthorizeCaps /\v<^(edit_(udp|user|view_html|web_settings))>/
syn match   confAuthorizeCaps /\v<^((export_results_is_visible|indexes_edit|input_file|license_(tab|edit|read|view_warnings)|web_debug))>/
syn match   confAuthorizeCaps /\v<^(list_(deployment_(client|server)|forwarders|httpauths|indexer(_cluster|discovery)|inputs))>/
syn match   confAuthorizeCaps /\v<^(list_(introspection|search_(head_clustering|scheduler)|settings|storage_passwords))>/
syn match   confAuthorizeCaps /\v<^((output_file|request_remote_tok|rest_(apps_(management|view)|properties_(g|s)et)|restart_splunkd))>/
syn match   confAuthorizeCaps /\v<^((rtsearch|run_debug_commands|schedule_(rt)?search|search(_process_config_refresh)?|use_file_operator))>/

" 7.3.0
syn match   confAuthorizeCaps /\v<^(edit_(tokens_(all|own|settings)|watchdog|local_apps))>/
syn match   confAuthorizeCaps /\v<^(edit_(search_concurrency_(all|scheduled)|metrics_rollup))>/
syn match   confAuthorizeCaps /\v<^(list_(pipeline_sets|tokens_(all|own|scs)))>/
syn match   confAuthorizeCaps /\v<^((upload_lookup_files|apps_restore|fsh_(search|manage)))>/

" 8.0.0
syn match   confAuthorizeStanzas contained /\v<(tokens_auth)>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(delete_messages|edit_(authentication_extensions|bookmarks_mc)|list_dist_peer|install_apps|metric_alerts))>/
syn match   confAuthorizeCaps /\v<^(edit_(authentication_extensions|bookmarks_mc)|list_dist_peer|install_apps|metric_alerts)>/

syn match   confAuthorizeConstants /\v<(enabled|disabled)$>/

" 8.1.0
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)edit_(log_alert_event|health_subset))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)(list_(health_subset|token_http)|pattern_detect|run_(msearch|walklex)))>/
syn match   confAuthorizeStanzas contained /\v<((role_|capability::)((list|edit)_workload_policy|edit_global_banner))>/

" 8.2
syn match   confAuthorizeStanzas contained /\v<(commands:user_configurable)>/

" Splunk version 6.
syn match   confAuthorizeStanzas /\v<((role_|capability::)list_accelerate_search)>/

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
hi def link confAuthorizeStanzas Identifier
hi def link confAuthorize Keyword
hi def link confAuthorizeCaps Type
hi def link confAuthorizeConstants Constant
