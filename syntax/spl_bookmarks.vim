" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" bookmarks.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confBookmarksStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confBookmarksStanzas contained /\v<(bookmarks_mc:[^\]]+)>/

" Key words
syn match   confBookmarks /\v<^(url)>/

" Highlights
hi def link confBookmarksStanzas Identifier
hi def link confBookmarks Keyword
hi def link confBookmarksConstants Constant
