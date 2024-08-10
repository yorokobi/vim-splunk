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
syn cluster confStanzas contains=confFederatedStanzas,confGenericStanzas

" federated.conf
syn match   confFederatedStanzas contained /\v<(provider|general)>/

syn match   confFederated /\v<^(type|ip|splunk\.(port|serviceAccount|app)|mode)>/
syn match   confFederated /\v<^(hostPort|serviceAccount|password|appContext|useFSHKnowledgeObjects)>/
syn match   confFederated /\v<^(needs_consent|heartbeat(Enabled|Interval)|connectivityFailuresThreshold)>/
syn match   confFederated /\v<^(controlCommands(Max(Threads|TimeThreshold)|FeatureEnabled))>/

syn match   confFederatedConstants /\v<(splunk|aws_s3|standard|transparent)$>/

" 9.3.0
syn match   confFederatedStanzas contained /\v<(s2s_standard_mode_unsupported_command:meta(data|search))>/
syn match   confFederatedStanzas contained /\v<(s2s_transparent_mode_unsupported_command:(makeresults|delete|dump|map|run(shellscript)?))>/
syn match   confFederatedStanzas contained /\v<(s2s_transparent_mode_unsupported_command:(script|send(alert|email)|rest|summarize|tstats))>/
syn match   confFederated /\v<^(proxyBundlesTTL|remoteEventsDownloadRetryCountMax|remoteEventsDownloadRetryTimeoutMs|verbose_mode)>/
syn match   confFederated /\v<^(max_preview_generation_duration|active|allow_target|rsh_min_version_(cloud|onprem))>/

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
hi def link confFederatedStanzas Identifier
hi def link confFederated Keyword
hi def link confFederatedConstants Constant
