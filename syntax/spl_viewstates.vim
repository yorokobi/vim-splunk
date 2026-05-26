" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" viewstates.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confViewStatesStanzas,confGenericStanzas

" Stanzas
" syn match   confViewStatesStanzas contained /\v<()>/

" Key words
" syn match   confViewStates /\v<^()>/

" Constants
" syn match   confViewStatesConstants /\v<()$>/

" Highlights
" hi def link confViewStatesStanzas Identifier
" hi def link confViewStates Keyword
" hi def link confViewStatesConstants Constant
