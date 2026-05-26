" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" procmon-filters.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confProcmonFiltersStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
" syn match   confProcmonFiltersStanzas contained /\v<()>/

" Key words
syn match   confProcmonFilters /\v<^(proc|type|hive)>/

" Constants
" syn match   confProcmonFiltersConstants /\v<()$>/

" Highlighting
hi def link confProcmonFiltersStanzas Identifier
hi def link confProcmonFilters Keyword
hi def link confProcmonFiltersConstants Constant
