" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" instance.cfg
" There's a fair chance some other highlighting scheme will take precendence
" over this one due to the .cfg file extension. ¯\_(ツ)_/¯

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confInstanceCfgStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
" syn match   confInstanceCfgStanzas contained /\v<()>/

" Key words
syn match   confInstanceCfg /\v<^(guid)>/

" Constants
" syn match   confInstanceCfgConstants /\v<()$>/

" Highlighting
hi def link confInstanceCfgStanzas Identifier
hi def link confInstanceCfg Keyword
"hi def link confInstanceCfgConstants Constant
