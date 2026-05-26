" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" tags.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confTagsStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
"syn match   confTagsStanzas contained /\v<()>/

" Key words
" syn match   confTags /\v<^()>/

" Constants
" syn match   confTagsConstants /\v<()$>/

" Highlighting
hi def link confTagsStanzas Identifier
hi def link confTags Keyword
hi def link confTagsConstants Constant
