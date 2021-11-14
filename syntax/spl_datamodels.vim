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
syn cluster confStanzas contains=confDatamodelsStanzas,confGenericStanzas

" datamodels.conf
syn match   confDatamodelsStanzas contained /\v<(default)>/
syn match   confDatamodels /\v<^(acceleration(\.(earliest|backfill|max)_time|\.poll_buckets_until_maxtime|\.cron_schedule|\.manual_rebuilds)?)>/
syn match   confDatamodels /\v<^(acceleration\.(max_concurrent|schedule_priority|hunk\.(compression_codec|dfs_block_size|file_format)|allow_skew))>/
syn match   confDatamodels /\v<^(dataset\.(description|type|commands|fields|display\.(diversity|sample_ratio|limiting|currentCommand|mode)))>/
syn match   confDatamodels /\v<^(dataset\.display\.datasummary\.(earliest|latest)Time|tags_whitelist)>/

" 7.2.3
syn match   confDatamodels /\v<^(acceleration\.allow_old_summaries)>/

syn match   confDatamodelsConstants /\v<(default|high(er|est)|latest|random|diverse|rare|data(model|summary)|table)$>/

" 7.3.0
syn match   confDatamodels /\v<^(acceleration\.workload_pool)>/

" 8.1.0
syn match   confDatamodels /\v<^(acceleration\.source_guid|strict_fields)>/

" 8.2
syn match   confDatamodels /\v<^(acceleration\.(store|external\.max_interval_per_summarization_run))>/

syn match   confDatamodelsConstants /\v<(splunk|external|orc|parquet)$>/

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
hi def link confDatamodelsStanzas Identifier
hi def link confDatamodels Keyword
hi def link confDatamodelsConstants Constant
