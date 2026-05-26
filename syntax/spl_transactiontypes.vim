" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" transactiontypes.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confTransactionTypesStanzas,confGenericStanzas

" Stanzas
" syn match   confTransactionTypesStanzas contained /\v<()>/

" Key words
syn match   confTransactionTypes /\v<^(max(events|pause|span|open(events|txn))|fields|connected)>/
syn match   confTransactionTypes /\v<^((start|end)swith|keepevicted|mvlist|delim|nullstr|search)>/

" Constants
" syn match   confTransactionTypesConstants /\v<()$>/

" Highlighting
hi def link confTransactionTypesStanzas Identifier
hi def link confTransactionTypes Keyword
hi def link confTransactionTypesConstants Constant
