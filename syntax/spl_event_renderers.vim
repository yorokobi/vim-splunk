" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" event_renderers.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confEventRenderersStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confEventRenderersStanzas contained /\v<()>/

" Key words
syn match   confEventRenderers /\v<^(eventtype|priority|template|css_class)>/

" Constants
" syn match   confEventRenderersConstants /\v<()$>/

" Highlighting
hi def link confEventRenderersStanzas Identifier
hi def link confEventRenderers Keyword
"hi def link confEventRenderersConstants Constant
