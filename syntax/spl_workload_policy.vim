" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" workload_policy.cof

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confWorkLoadPolicyStanzas,confGenericStanzas

" Stanzas
syn match   confWorkLoadPolicyStanzas contained /\v<(search_admission_control)>/

" Key words
syn match   confWorkLoadPolicy /\v<^(admission_rules_enabled)>/

" Constants
" syn match   confWorkLoadPolicyConstants /\v<()$>/

" Highlighting
hi def link confWorkLoadPolicyStanzas Identifier
hi def link confWorkLoadPolicy Keyword
hi def link confWorkLoadPolicyConstants Constant
