" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" workload_rules.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confWorkLoadRulesStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confWorkLoadRulesStanzas contained /\v<(workload_rule:[^]]+|workload_rules_order)>/
syn match   confWorkLoadRulesStanzas contained /\v<(search_filter_rule:[^]]+)>/

" Key words
syn match   confWorkLoadRules /\v<^(predicate|workload_pool|rules|action|schedule|(end|start)_time|every_(week|month)_days|user_message)>/
syn match   confWorkLoadRules /\v<^((start|end)_date|numeric_search_time_range)>/

" Constants
syn match   confWorkLoadRulesConstants /\v<(alert|move|abort|always_on|time_range|every_(day|week|month)|queue|filter)$>/

" Highlighting
hi def link confWorkLoadRulesStanzas Identifier
hi def link confWorkLoadRules Keyword
hi def link confWorkLoadRulesConstants Constant
