" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

if version < 600
    syntax clear
elseif exists("b:current_syntax")
    finish
endif

setlocal iskeyword+=.
setlocal iskeyword+=:
setlocal iskeyword+=-

syn case match

syn match confComment /^#.*/ contains=confTodo oneline display
syn match confSpecComment /^\s.*/ contains=confTodo oneline display
syn match confSpecComment /^\*.*/ contains=confTodo oneline display

syn region confString start=/"/ skip="\\\"" end=/"/ oneline display contains=confNumber,confVar
syn region confString start=/`/             end=/`/ oneline display contains=confNumber,confVar
syn region confString start=/'/ skip="\\'"  end=/'/ oneline display contains=confNumber,confVar
syn match  confNumber /\v[+-]?\d+([ywdhsm]|m(on|ins?))(\@([ywdhs]|m(on|ins?))\d*)?>/
syn match  confNumber /\v[+-]?\d+(\.\d+)*>/
syn match  confNumber /\v<\d+[TGMK]B>/
syn match  confNumber /\v<\d+(k)?b>/
syn match  confPath   ,\v(^|\s|\=)\zs(file:|https?:|\$\k+)?(/+\k+)+(:\d+)?,
syn match  confPath   ,\v(^|\s|\=)\zsvolume:\k+(/+\k+)+,
syn match  confVar    /\$\k\+\$/

syn keyword confBoolean on off t[rue] f[alse] T[rue] F[alse]
syn keyword confTodo FIXME[:] NOTE[:] TODO[:] CAUTION[:] contained

" Define generic stanzas
syn match confGenericStanzas display contained /\v[^\]]+/

" Define stanzas
syn region confStanza matchgroup=confStanzaStart start=/^\[/ matchgroup=confStanzaEnd end=/\]/ oneline transparent contains=@confStanzas

" Group clusters
syn cluster confStanzas contains=confPropsStanzas,confGenericStanzas

" props.conf
syn match   confPropsStanzas contained /\v<(default)>/
syn match   confProps /\v<^(ADD_EXTRA_TIME_FIELDS|ANNOTATE_PUNCT|AUTO_KV_JSON|BREAK_ONLY_BEFORE(_DATE)?|CHARSET|CHECK_(FOR_HEADER|METHOD)|DATETIME_CONFIG)>/
syn match   confProps /\v<^(EVENT_BREAKER(_ENABLE)?|(HEADER_)?FIELD_(DELIMITER|HEADER_REGEX|NAMES|QUOTE)|HEADER_(FIELD_LINE_NUMBER|MODE)|INDEXED_EXTRACTIONS)>/
syn match   confProps /\v<^(JSON_TRIM_BRACES_IN_ARRAY_NAMES|KV_(MODE|TRIM_SPACES)|LEARN_(MODEL|SOURCETYPE)|LINE_BREAKER(_LOOKBEHIND)?|MATCH_LIMIT)>/
syn match   confProps /\v<^(MAX_(DAYS_(AGO|HENCE)|DIFF_SECS_(AGO|HENCE)|EVENTS|TIMESTAMP_LOOKAHEAD)|METRICS_PROTOCOL|(MISSING_VALUE|PREAMBLE)_REGEX)>/
syn match   confProps /\v<^(MUST_(BREAK_AFTER|NOT_BREAK_(AFTER|BEFORE))|NO_BINARY_CHECK|PREFIX_SOURCETYPE|SEGMENTATION|SHOULD_LINEMERGE|STATSD-DIM-TRANSFORMS)>/
syn match   confProps /\v<^(TIME(STAMP_FIELDS|_(FORMAT|PREFIX))|TRUNCATE|TZ(_ALIAS)?)>/
syn match   confProps /\v<^(_actions|category|description|detect_trailing_nulls|force_local_processing|given_type|initCrcLength|invalid_cause|is_valid)>/
syn match   confProps /\v<^(maxDist|priority|pulldown_type|rename|sourcetype|unarchive_(cmd|sourcetype))>/

" ----------
"  7.1
" ----------
syn match   confProps /\v<^(DEPTH_LIMIT)>/

syn match   confComplex /\v<^((EXTRACT|REPORT|TRANSFORMS)-[^=]+)>/
syn match   confComplex /\v<^((EVAL|FIELDALIAS|SEDCMD|SEGMENTATION)-[0-9A-Za-z_-]+)>/
syn match   confComplex /\v<^(\c(LOOKUP)(-)?[^=]+)>/
syn match   confComplex /\v<^(MORE|LESS)_THAN(\S+_)?\d+>/
syn keyword confComplex AS OUTPUT OUTPUTNEW

syn match   confPropsConstants /\v<((endpoint|entire)_md5|modtime|always|firstline|none|auto(_escaped)?|multi|STATSD|COLLECTD_HTTP)$>/

" 7.2.3
syn match   confProps /\v<^(METRIC-SCHEMA-TRANSFORMS)>/

" 8.0.0
syn match   confProps /\v<^(HEADER_FIELD_ACCEPTABLE_SPECIAL_CHARACTERS)>/

" 8.1.0
syn match   confProps /\v<^(LB_CHUNK_BREAKER|STATSD_EMIT_SINGLE_MEASUREMENT_FORMAT|termFrequencyWeightedDist)>/
syn keyword confComplex ASNEW

syn case ignore
syn match   confPropsConstants /\v<((c|t|p)sv|w3c|json|xml|hec)$>/
syn case match

" Highlight definitions (generic)
hi def link confComment Comment
hi def link confSpecComment Error
hi def link confBoolean Boolean
hi def link confTodo Todo

" Other highlight
hi def link confString String
hi def link confNumber Number
hi def link confPath   Number
hi def link confVar    PreProc

hi def link confStanzaStart Delimiter
hi def link confstanzaEnd Delimiter

" Highlight for stanzas
hi def link confStanza Function
hi def link confGenericStanzas Constant
hi def link confPropsStanzas Identifier
hi def link confProps Keyword
hi def link confPropsConstants Constant
hi def link confComplex Preproc
