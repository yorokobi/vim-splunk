" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" health.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confHealthStanzas,confHealthDeprecatedStanzas,confCommanStanzas,confGenericStanzas

" Stanzas
syn match   confHealthStanzas contained /\v<(health_reporter|clustering|feature:\k+|alert_action:\k+)>/
syn match   confHealthStanzas contained /\v<(distributed_health_reporter|tree_view:health_subset|data_management_health_reporter)>/

" Key words
syn match   confHealth /\v<^(full_health_log_interval|suppress_status_update_ms|health_report_period|disabled|indicator:\S+:(yellow|red))>/
syn match   confHealth /\v<^(alert\.(disabled|actions|min_duration_sec|threshold_color|suppress_period)|display_name)>/
syn match   confHealth /\v<^(indicator:\S+:description|alert:\S+\.(disabled|min_duration_sec|threshold_color)|action\.\S+)>/
syn match   confHealth /\v<^(indicator:\S+:indicator|tree_view:health_subset)>/
syn match   confHealth /\v<^(latency_tracker_log_interval_sec|aggregate_ingestion_latency_health)>/
syn match   confHealth /\v<^(latency_tracker_log_interval|ingestion_latency_send_interval(_max)?|snooze_end_time|friendly_description)>/
syn match   confHealth /\v<^(indicator:\S+:friendly_description|distributed_disabled|suppress_status_reason_update_s)>/

" Constants
syn match   confHealthConstants /\v<(yellow|red)$>/

" Deprecated
syn match   confHealthDeprecatedStanzas contained /\v<(feature:(master_connectivity|slave_(state|version)))>/

" Highlighting
hi def link confHealthStanzas Identifier
hi def link confHealth Keyword
hi def link confHealthConstants Constant
hi def link confHealthDeprecatedStanzas Removed
