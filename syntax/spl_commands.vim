" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" commands.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confCommandsStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
" syn match   confCommandsStanzas contained /\v<()>/

" Key words
syn match   confCommands /\v<^(filename|command\.arg\.\d|local|perf_warn_limit|streaming|maxinputs|passauth|run_in_preview|pass_timezone)>/
syn match   confCommands /\v<^(enableheader|retainsevents|generating|(generates|overrides)_timeorder|(requires|streaming)_preop)>/
syn match   confCommands /\v<^(required_fields|supports_(multivalues|getinfo|rawargs)|undo_scheduler_escaping|requires_srinfo|needs_empty_results)>/
syn match   confCommands /\v<^(changes_colorder|outputheader|clear_required_fields|stderr_dest|is_(order_sensitive|risky)|chunked|max(wait|chunksize))>/

" Constants
syn match   confCommandsConstants /\v<(log|message|none)$>/

" Highlighting
hi def link confCommandsStanzas Identifier
hi def link confCommands Keyword
hi def link confCommandsConstants Constant
