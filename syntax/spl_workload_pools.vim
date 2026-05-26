" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" workload_pools.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confWorkLoadPoolsStanzas,confCommonStanzas,confGenericStanzas

" workload_pools.conf
syn match   confWorkLoadPoolsStanzas contained /\v<(workload_pool:[^\]]+|workload_category:[^\]]+)>/

syn match   confWorkLoadPools /\v<^((default|ingest)_pool|workload_pool_base_dir_name|(cpu|mem)_weight)>/
syn match   confWorkLoadPools /\v<^(category|default_category_pool|allow_basic|threaded)>/

" Highlighting
hi def link confWorkLoadPoolsStanzas Identifier
hi def link confWorkLoadPools Keyword
" hi def link confWorkLoadPoolsConstants Constant
