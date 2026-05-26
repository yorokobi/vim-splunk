" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" source-classifier.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confSourceClassifierStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
" syn match   confSourceClassifierStanzas contained /\v<()>/

" Key words
syn match   confSourceClassifier /\v<^(ignored_(model|filename)_keywords)>/

" Constants
" syn match   confSourceClassifierConstants /\v<()$>/

" Highlighting
hi def link confSourceClassifierStanzas Identifier
hi def link confSourceClassifier Keyword
hi def link confSourceClassifierConstants Constant
