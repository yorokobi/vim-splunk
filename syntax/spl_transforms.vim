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
syn cluster confStanzas contains=confTransformsStanzas,confGenericStanzas

" transforms.conf
syn match   confTransformsStanzas contained /\v<(default|accepted_keys|statsd-dims:[^]]+)>/

syn match   confTransforms /\v<^(CAN_OPTIMIZE|CLEAN_KEYS|CLONE_SOURCETYPE|DEFAULT_VALUE|DELIMS|(DEST|SOURCE)_KEY|FIELDS|FORMAT|KEEP_EMPTY_VALS|LOOKAHEAD)>/
syn match   confTransforms /\v<^(MATCH_LIMIT|MV_ADD|REGEX|REMOVE_DIMS_FROM_METRIC_NAME|REPEAT_MATCH|WRITE_META)>/
syn match   confTransforms /\v<^(allow_caching|batch_index_query|(case_sensitive|default)_match|check_permission|collection)>/
syn match   confTransforms /\v<^(external_(cmd|type)|feature_id_element|(index_)?fields_list|filename|filter|match_type|max_ext_batch|(max|min)_(matches|offset_secs))>/
syn match   confTransforms /\v<^(replicate|time_(field|format))>/

" ----------
"  7.1
" ----------
syn match   confTransforms /\v<^(DEPTH_LIMIT)>/

syn match   confTransformsConstants /\v<(python|executable|kvstore|geo(_hex)?|queue|_(raw|meta|time|MetaData:Index|(TCP|SYSLOG)_ROUTING)|MetaData:(Host|Source(type)?))$>/

syn match confComplex /\v<_(KEY|VAL)_\k+>/

" 7.2.3
syn match   confTransforms /\v<^(INGEST_EVAL|cache_size|METRIC-SCHEMA-(MEASURES|BLACKLIST-DIMS))>/
syn match   confComplex /\v<METRIC-SCHEMA-(MEASURES|BLACKLIST-DIMS)-\k+>/
syn match   confTransformsStanzas contained /\v<(metric-schema:[^]]+)>/

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
hi def link confComplex Preproc

hi def link confStanzaStart Delimiter
hi def link confstanzaEnd Delimiter

" Highlight for stanzas
hi def link confStanza Function
hi def link confGenericStanzas Constant
hi def link confTransformsStanzas Identifier
hi def link confTransforms Keyword
hi def link confTransformsConstants Constant
