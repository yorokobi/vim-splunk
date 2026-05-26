" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" wmi.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confWMIStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confWMIStanzas contained /\v<(settings|WMI:[^]]+)>/

" Key words
syn match   confWMI /\v<^(initial_backoff|max_(retries_at_max_)?backoff|checkpoint_sync_interval|server|interval|disabled|hostname|current_only)>/
syn match   confWMI /\v<^(use_(old_eventlog_api|threads)|thread_wait_time_msec|suppress_(checkpoint|keywords|type|task|opcode|sourcename)|batch_size|index)>/
syn match   confWMI /\v<^(checkpointInterval|event_log_file|disable_hostname_normalization|wql|namespace)>/

" Constants
syn match   confWMIConstants /\v<(Application|System|Security)$>/

" Highlighting
hi def link confWMIStanzas Identifier
hi def link confWMI Keyword
hi def link confWMIConstants Constant
