" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" fields.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confFieldsStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
" syn match   confFieldsStanzas contained /\v<()>/

" Key words
syn match   confFields /\v<^(TOKENIZER|INDEXED(_VALUE)?)>/

" Constants
" syn match   confFieldsConstants /\v<()$>/

" Highlighting
hi def link confFieldsStanzas Identifier
hi def link confFields Keyword
hi def link confFieldsConstants Constant
