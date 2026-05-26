" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" transforms.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confTransformsStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confTransformsStanzas contained /\v<(accepted_keys|statsd-dims:[^]]+|metric-schema:[^]]+|_ruleset:global_settings)>/

" Key words
syn match   confTransforms /\v<^(CAN_OPTIMIZE|CLEAN_KEYS|CLONE_SOURCETYPE|DEFAULT_VALUE|DELIMS|(DEST|SOURCE)_KEY)>/
syn match   confTransforms /\v<^(FIELDS|FORMAT|KEEP_EMPTY_VALS|LOOKAHEAD)>/
syn match   confTransforms /\v<^(MATCH_LIMIT|MV_ADD|REGEX|REMOVE_DIMS_FROM_METRIC_NAME|REPEAT_MATCH|WRITE_META)>/
syn match   confTransforms /\v<^(allow_caching|batch_index_query|(case_sensitive|default)_match|check_permission|collection)>/
syn match   confTransforms /\v<^(external_(cmd|type)|feature_id_element|(index_)?fields_list|filename|filter)>/
syn match   confTransforms /\v<^(match_type|max_ext_batch|(max|min)_(matches|offset_secs))>/
syn match   confTransforms /\v<^(replicate|time_(field|format)|DEPTH_LIMIT)>/
syn match   confTransforms /\v<^(INGEST_EVAL|cache_size|METRIC-SCHEMA-(MEASURES|BLACKLIST-DIMS))>/
syn match   confTransforms /\v<^(reverse_lookup_honor_case_sensitive_match|METRIC-SCHEMA-WHITELIST-DIMS)>/
syn match   confTransforms /\v<^(STOP_PROCESSING_IF|metrics.(disabled|report_interval|rule_filter))>/
syn match   confTransforms /\v<^(CAN_OPTIMIZE_IE|max_duplicates|python\.required)>/

" Constants
syn match   confTransformsConstants /\v<(python|executable|kvstore|geo(_hex)?|queue|_(raw|meta|time|_MetaData:Index))$>/
syn match   confTransformsConstants /\v<((_ALLNUMS_|_NUMS_EXCEPT_)|(TCP|SYSLOG)_ROUTING|MetaData:(Host|Source(type)?))>/

" Complex keys
syn match   confComplex /\v<(METRIC-SCHEMA-(MEASURES|(WHITE|BLACK)LIST-DIMS)-\k+|_(KEY|VAL)_\k+)>/

" Highlighting
hi def link confTransformsStanzas Identifier
hi def link confTransforms Keyword
hi def link confTransformsConstants Constant
hi def link confComplex PreProc
