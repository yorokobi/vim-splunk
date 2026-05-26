" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" eventdiscoverer.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confEventDiscovererStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
" syn match   confEventDiscovererStanzas contained /\v<()>/

" Key words
syn match   confEventDiscoverer /\v<^(ignored_(keywords|fields)|important_keywords)>/

" Constants
" syn match   confEventDiscovererConstants /\v<()$>/

" Highlighting
hi def link confEventDiscovererStanzas Identifier
hi def link confEventDiscoverer Keyword
hi def link confEventDiscovererConstants Constant
