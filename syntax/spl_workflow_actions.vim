" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" workflow_actions.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confWorkflowActionsStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
" syn match   confWorkflowActionsStanzas contained /\v<()>/

" Key words
syn match   confWorkflowActions /\v<^(type|label|fields|eventtypes|display_location|disabled|link\.(uri|target|method|postargs\.\d+\.[^\ |\=]+))>/
syn match   confWorkflowActions /\v<^(search\.(search_string|app|view|target|earliest|latest|preserve_timerange))>/

" Constants
" syn match   confWorkflowActionsConstants /\v<()$>/

" Highlighting
hi def link confWorkflowActionsStanzas Identifier
hi def link confWorkflowActions Keyword
hi def link confWorkflowActionsConstants Constant
