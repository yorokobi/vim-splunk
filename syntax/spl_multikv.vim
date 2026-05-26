" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" multikv.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confMultiKVStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
" syn match   confMultiKVStanzas contained /\v<()>/

" Key words
syn match   confMultiKV /\v<^(\S+\.(start(_offset)?|member|end|linecount|ignore|replace|tokens))>/

" Constants
syn match   confMultiKVConstants /\v<(_(all|none)_)$>/
syn match   confMultiKVConstants /\v<(_(align|chop|token_list|regex|tokenize)_)>/

" Highlighting
hi def link confMultiKVStanzas Identifier
hi def link confMultiKV Keyword
hi def link confMultiKVConstants Constant
