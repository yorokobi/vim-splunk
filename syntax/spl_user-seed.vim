" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" user-seed.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters -- confCommonStanzas omitted
syn cluster confStanzas contains=confUserSeedStanzas,confGenericStanzas

" Stanzas
syn match   confUserSeedStanzas contained /\v<(user_info)>/

" Key words
syn match   confUserSeed /\v<^(USERNAME|(HASHED_)?PASSWORD)>/

" Constants
" syn match   confUserSeedConstants /\v<()$>/

hi def link confUserSeedStanzas Identifier
hi def link confUserSeed Keyword
hi def link confUserSeedConstants Constant
