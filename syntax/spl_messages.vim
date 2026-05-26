" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" messages.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confMessagesStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
" syn match   confMessagesStanzas contained /\v<()>/

" Key words
syn match   confMessages /\v<^(name|message(_alternate)?|action|severity|capabilities|roles|help|target)>/

" Constants
syn match   confMessagesConstants /\v<(critical|error|warn|info|debug)$>/
syn match   confMessagesConstants /\v<(auto|ui|log|ui\,log|none)$>/

" Highlighting
hi def link confMessagesStanzas Identifier
hi def link confMessages Keyword
hi def link confMessagesConstants Constant
