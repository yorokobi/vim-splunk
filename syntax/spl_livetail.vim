" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" livetail.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confLivetailStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
" syn match   confLivetailStanzas contained /\v<()>/

" Key words
syn match   confLivetail /\v<^(sound-(ding|airhorn|alarm)|threshold|(play)?sound|flash|color|keyphrase)>/

" Constants
" syn match   confLivetailConstants /\v<()$>/

" Highlighting
hi def link confLivetailStanzas Identifier
hi def link confLivetail Keyword
hi def link confLivetailConstants Constant
