" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" segmenters.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confSegmentersStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
" syn match   confSegmentersStanzas contained /\v<()>/

" Key words
syn match   confSegmenters /\v<^(MAJOR(_LEN|_COUNT)?|MINOR(_LEN|_COUNT)?|INTERMEDIATE_MAJORS|FILTER|LOOKAHEAD)>/

" Constants
" syn match   confSegmentersConstants /\v<()$>/

" Highlighting
hi def link confSegmentersStanzas Identifier
hi def link confSegmenters Keyword
hi def link confSegmentersConstants Constant
