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
syn cluster confStanzas contains=confHealthStanzas,confGenericStanzas

" health.conf
syn match   confHealthStanzas contained /\v<(default|health_reporter|clustering|feature:\k+|alert_action:\k+)>/

syn match   confHealth /\v<^(full_health_log_interval|suppress_status_update_ms|health_report_period|disabled|indicator:\S+:(yellow|red))>/

" 7.3.0
syn match   confHealth /\v<^(alert\.(disabled|actions|min_duration_sec|threshold_color|suppress_period)|display_name)>/
syn match   confHealth /\v<^(indicator:\S+:description|alert:\S+\.(disabled|min_duration_sec|threshold_color)|action\.\S+)>/

syn match   confHealthConstants /\v<(yellow|red)$>/

" 8.0.0
syn match   confHealthStanzas contained /\v<(distributed_health_reporter)>/

" 8.1.0
syn match   confHealthStanzas contained /\v<(tree_view:health_subset)>/
syn match   confHealth /\v<^(indicator:\S+:indicator|tree_view:health_subset)>/
syn match   confHealthConstants /\v<(enabled|disabled)$>/

" 8.2
syn match   confHealth /\v<^(latency_tracker_log_interval_sec|aggregate_ingestion_latency_health)>/

" 9.0.0
syn match   confHealth /\v<^(latency_tracker_log_interval|ingestion_latency_send_interval(_max)?|snooze_end_time|friendly_description)>/
syn match   confHealth /\v<^(indicator:\S+:friendly_description)>/

" 9.1.0
syn match   confHealth /\v<^(distributed_disabled)>/

" 9.4.0
syn match   confHealth /\v<^(suppress_status_reason_update_s)>/

" 10.0.0
syn match   confHealthStanzas contained /\v<(data_management_health_reporter)>/

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
hi def link confHealthStanzas Identifier
hi def link confHealth Keyword
hi def link confHealthConstants Constant
