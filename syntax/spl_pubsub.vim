" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" pubsub.conf -- DEPRECATED?

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confPubSubStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confPubSubStanzas contained /\v<(pubsub-server:(deploymentServer|direct))>/

" Key words
syn match   confPubSub /\v<^(targetUri)>/

" Constants
syn match   confPubSubConstants /\v<(direct)$>/

" Highlighting
hi def link confPubSubStanzas Identifier
hi def link confPubSub Keyword
hi def link confPubSubConstants Constant
