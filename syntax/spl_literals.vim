" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" literals.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confLiteralsStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
" syn match   confLiteralsStanzas contained /\v<()>/

" Key words
" syn match   confLiterals /\v<^()>/

" Constants
" syn match   confLiteralsConstants /\v<()$>/

" Highlighting
" hi def link confLiteralsStanzas Identifier
" hi def link confLiterals Keyword
" hi def link confLiteralsConstants Constant
