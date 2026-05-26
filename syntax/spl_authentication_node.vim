" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" authentication_node.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confAuthenticationNodeStanzas,confGenericStanzas

" Stanzas
syn match  confAuthenticationNodeStanzas contained /\v<(client_\k+)>/

" Key words
syn match  confAuthenticationNode /\v<^(id|grantTypes|jwks|roles|tokenEndpointAuthMethod|instanceId|redirectUris)>/
syn match  confAuthenticationNode /\v<^(responseTypes|scopes)>/

" Constants
" syn match  confAuthenticationNodeConstants /\v<()$>/

" Highlighting
hi def link confAuthenticationNodeStanzas Identifier
hi def link confAuthenticationNodeConstants Constant
hi def link confAuthenticationNode Keyword
