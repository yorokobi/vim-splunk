" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" searchbnf.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confSearchBNFStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confSearchBNFStanzas contained /\v<(\S+-command)>/

" Key words
syn match   confSearchBNF /\v<^((simple)?syntax|alias|description|shortdesc|(example|comment)[^\ |\=]+|usage|tags|related)>/
syn match   confSearchBNF /\v<^((appears|optout)-in|category|maintainer|note|supports-multivalue)>/

" Constants
syn match   confSearchBNFConstants /\v<(public|private|deprecated)$>/

" Highlighting
hi def link confSearchBNFStanzas Identifier
hi def link confSearchBNF Keyword
hi def link confSearchBNFConstants Constant
