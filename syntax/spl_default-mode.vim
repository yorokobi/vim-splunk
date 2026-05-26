" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" default-mode.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confDefaultModeStanzas,confCommonStanzas,confGenericStanzas

" default-mode.conf

" Stanzas
syn match   confDefaultModeStanzas contained /\v<(pipeline:[^]]+)>/

" Key words
syn match   confDefaultMode /\v<^(disabled_processors)>/

" Constants
" syn match   confDefaultModeConstants /\v<()$>/

" Highlighting
hi def link confDefaultModeStanzas Identifier
hi def link confDefaultMode Keyword
" hi def link confDefaultModeConstants Constant
