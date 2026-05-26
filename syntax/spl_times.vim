" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" times.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confTimesStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confTimesStanzas contained /\v<(settings)>/

" Key words
syn match   confTimes /\v<^((header_)?label|(earliest|latest)_time|order)>/
syn match   confTimes /\v<^(show_(advanced|date(time)?_range|presets|realtime|relative))>/

" Constants
" syn match   confTimesConstants /\v<()$>/

" Deprecated
syn match   confDeprecated /\v<^((is_)?sub_menu)>/

" Highlighting
hi def link confTimesStanzas Identifier
hi def link confTimes Keyword
hi def link confTimesConstants Constant
hi def link confDeprecated Removed
