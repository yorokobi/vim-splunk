" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" eventtypes.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confEventTypesStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
" syn match   confEventTypesStanzas contained /\v<()>/

" Key words
syn match   confEventTypes /\v<^(search|priority|description|color)>/

" Constants
" syn match   confEventTypesConstants /\v<()$>/

" Deprecated
syn match   confDeprecated /\v<^(tags)>/

" Highlighting
hi def link confEventTypesStanzas Identifier
hi def link confEventTypes Keyword
hi def link confEventTypesConstants Constant
hi def link confDeprecated Removed
