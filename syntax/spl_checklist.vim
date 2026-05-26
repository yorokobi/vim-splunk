" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" checklist.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confChecklistStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
" syn match   confChecklistStanzas contained /\v<()>/

" Key words
syn match   confChecklist /\v<^(applicable_to_groups|category|description|doc_(link|title)|drilldown|environments_to_exclude|failure_text)>/
syn match   confchecklist /\v<^(search|suggested_action|tags|title)>/

" Highlighting
hi def link confChecklistStanzas Identifier
hi def link confChecklist Keyword
hi def link confChecklistConstants Constant
