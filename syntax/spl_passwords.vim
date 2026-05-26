" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" passwords.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confPasswordsStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confPasswordsStanzas contained /\v<(credential:[^\]]+)>/

" Key words
syn match   confPasswords /\v<^(password)>/

" Constants
" syn match   confPasswordsConstants /\v<()$>/

" Highlighting
hi def link confPasswordsStanzas Identifier
hi def link confPasswords Keyword
hi def link confPasswordsConstants Constant
