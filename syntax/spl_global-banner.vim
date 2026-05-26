" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" global-banner.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confGlobalbannerStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confGlobalbannerStanzas contained /\v<(BANNER_MESSAGE_SINGLETON)>/

" Key words
syn match   confGlobalbanner /\v<^(global_banner\.(visible|message|background_color|hyperlink(_text)?))>/

" Constants
syn match   confGlobalbannerConstants /\v<(green|blue|yellow|orange|red)$>/

" Highlighting
hi def link confGlobalbannerStanzas Identifier
hi def link confGlobalbanner Keyword
hi def link confGlobalbannerConstants Constant
