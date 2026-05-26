" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" collections.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confCollectionsStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
" syn match   confCollectionsStanzas contained /\v<()>/

" Key words
syn match   confCollections /\v<^(enforceTypes|field\.[^\ |\=]+|accelerated_fields\.[^\ |\=]+|profiling(Enabled|ThresholdMs)|replicate)>/
syn match   confCollections /\v<^(replication_dump_(strategy|maximum_file_size))>/

" Constants
syn match   confCollectionsConstants /\v<(number|bool|string|time|internal_cache|undefined|one_file|auto)$>/

" Highlighting
hi def link confCollectionsStanzas Identifier
hi def link confCollections Keyword
hi def link confCollectionsConstants Constant
