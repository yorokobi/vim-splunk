" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" sourcetypes.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confSourcetypesStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
" syn match   confSourcetypesStanzas contained /\v<()>/

" Key words
syn match   confSourcetypes /\v<^(_source(type)?)>/

" Constants
"syn match   confSourcetypesConstants /\v<()$>/

" Highlighting
hi def link confSourcetypesStanzas Identifier
hi def link confSourcetypes Keyword
hi def link confSourcetypesConstants Constant
