" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" field_filters.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confFieldFiltersStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confFieldFiltersStanzas contained /\v<(default)>/

" Key words
syn match   confFieldFilters /\v<^(action|limit|roleExemptions)>/

" Constants
" syn match   confFieldFiltersConstants /\v<()$>/

" Highlighting
hi def link confFieldFiltersStanzas Identifier
hi def link confFieldFilters_Constants Constant
hi def link confFieldFilters Keyword
