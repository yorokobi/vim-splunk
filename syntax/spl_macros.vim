" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" macros.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confMacrosStanzas,confGenericStanzas

" Stanzas
" syn match   confMacrosStanzas contained /\v<()>/

" Key words
syn match   confMacros /\v<^(args|definition|validation|errormsg|iseval)>/

" Constants
" syn match   confMacrosConstants /\v<()$>/

" Highlighting
hi def link confMacrosStanzas Identifier
hi def link confMacros Keyword
hi def link confMacrosConstants Constant
