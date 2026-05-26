" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" props.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confPropsStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confPropsStanzas contained /\v<()>/

" Key words
syn match   confProps /\v<^(ADD_EXTRA_TIME_FIELDS|ANNOTATE_PUNCT|AUTO_KV_JSON|BREAK_ONLY_BEFORE(_DATE)?|CHARSET|CHECK_(FOR_HEADER|METHOD))>/
syn match   confProps /\v<^(EVENT_BREAKER(_ENABLE)?|(HEADER_)?FIELD_(DELIMITER|HEADER_REGEX|NAMES|QUOTE)|HEADER_(FIELD_LINE_NUMBER|MODE))>/
syn match   confProps /\v<^(JSON_TRIM_BRACES_IN_ARRAY_NAMES|KV_(MODE|TRIM_SPACES)|LEARN_(MODEL|SOURCETYPE)|LINE_BREAKER(_LOOKBEHIND)?|MATCH_LIMIT)>/
syn match   confProps /\v<^(MAX_(DAYS_(AGO|HENCE)|DIFF_SECS_(AGO|HENCE)|EVENTS|TIMESTAMP_LOOKAHEAD)|METRICS_PROTOCOL|(MISSING_VALUE|PREAMBLE)_REGEX)>/
syn match   confProps /\v<^(MUST_(BREAK_AFTER|NOT_BREAK_(AFTER|BEFORE))|NO_BINARY_CHECK|PREFIX_SOURCETYPE|SEGMENTATION|SHOULD_LINEMERGE)>/
syn match   confProps /\v<^(TIME(STAMP_FIELDS|_(FORMAT|PREFIX))|TRUNCATE|TZ(_ALIAS)?|DATETIME_CONFIG|INDEXED_EXTRACTIONS)>/
syn match   confProps /\v<^(_actions|category|description|detect_trailing_nulls|force_local_processing|given_type|initCrcLength|invalid_cause)>/
syn match   confProps /\v<^(maxDist|priority|pulldown_type|rename|sourcetype|unarchive_(cmd|sourcetype)|DEPTH_LIMIT)>/
syn match   confProps /\v<^(METRIC-SCHEMA-TRANSFORMS|HEADER_FIELD_ACCEPTABLE_SPECIAL_CHARACTERS|DETERMINE_TIMESTAMP_DATE_WITH_SYSTEM_TIME)>/
syn match   confProps /\v<^(LB_CHUNK_BREAKER_TRUNCATE|STATSD_EMIT_SINGLE_MEASUREMENT_FORMAT|termFrequencyWeightedDist)>/
syn match   confProps /\v<^(ROUTE_EVENTS_OLDER_THAN|unarchive_cmd_start_mode|OPTIMIZE_IE_EXTRACT|trackPipelineLatency)>/
syn match   confProps /\v<^(MAX_EXPECTED_EVENT_LINES|SOURCETYPE_NAME_RESTRICTED_CHARACTERS|is_valid|STATSD-DIM-TRANSFORMS)>/
syn match   confProps /\v<^(XML_INDEXED_EXTRACTIONS_PIPELINE|extraction_cutoff|XML_IE_(IN|EX)CLUDE)>/

" Complex keys
syn match   confComplex /\v<^((EXTRACT|REPORT|TRANSFORMS)-[0-9A-Za-z_-]+)>/
syn match   confComplex /\v<^((EVAL|FIELDALIAS|SEDCMD|SEGMENTATION)-[0-9A-Za-z_-]+)>/
syn match   confComplex /\v<^(\c(LOOKUP)(-)?[^=]+)>/
syn match   confComplex /\v<^(MORE|LESS)_THAN(\S+_)?\d+>/
syn match   confComplex /\v<^(RULESET(_DESC)?-[0-9A-Za-z_-]+)>/
syn keyword confComplex AS OUTPUT OUTPUTNEW ASNEW

" Constants
syn match   confPropsConstants /\v<((endpoint|entire)_md5|modtime|always|firstline|none|auto(_escaped)?|multi|STATSD)$>/
syn case ignore
syn match   confPropsConstants /\v<((c|t|p)sv|w3c|json|xml|hec)$>/
syn case match
syn match   confPropsConstants /\v<(direct|shell|COLLECTD_HTTP|NONE|CURRENT|subseconds|all)$>/
syn match   confPropsConstants /\v<(XML(KV(-WINEVT)?)?|structuredparsing|wineventlog|typing|exec)$>/

" Deprecated
syn match   confPropsDeprecated /\v<^(LB_CHUNK_BREAKER)>/

" Highlighting
hi def link confPropsStanzas Identifier
hi def link confProps Keyword
hi def link confPropsConstants Constant
hi def link confComplex Preproc
hi def link confPropsDeprecated Removed
