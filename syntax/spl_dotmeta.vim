" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" default.meta, local.meta

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confMetaFilesStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confMetaFilesStanzas contained /\v<(views(\/[^\]]+)?)>/

" Key words
syn match   confMetaFiles /\v<^(access|export|owner)>/

" Constants
syn match   confMetaFilesConstants /\v<(read(\s)?:|write(\s)?:|system|admin|power)>/

" Highlighting
hi def link confMetaFilesStanzas Identifier
hi def link confMetaFiles Keyword
hi def link confMetaFilesConstants Constant
