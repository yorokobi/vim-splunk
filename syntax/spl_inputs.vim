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
syn keyword confTodo FIXME[:] NOTE[:] TODO[:] contained

" Define generic stanzas
syn match confGenericStanzas display contained /\v[^\]]+/

" Define stanzas
syn region confStanza matchgroup=confStanzaStart start=/^\[/ matchgroup=confStanzaEnd end=/\]/ oneline transparent contains=@confStanzas

" Group clusters
syn cluster confStanzas contains=confInputsStanzas,confGenericStanzas

" inputs.conf
syn match   confInputsStanzas contained /\v<(default|blacklist:[^]]+|tcp(-ssl)?:(\/\/\w+:)?\d+|udp:(\/\/\w+:)?\d+|splunktcp((-ssl)?:(\/\/\w+:)?\d+)?)>/
syn match   confInputsStanzas contained /\v<(batch|monitor|fifo|script|perfmon|splunktcptoken|MonitorNoHandle|Win(EventLog|(Host|Net|Print|Reg)Mon)):\/\/[^]]+>/
syn match   confInputsStanzas contained /\v<(admon|powershell(2)?):\/\/[^]]+>/
syn match   confInputsStanzas contained /\v<(SSL|fschange:[^]]+|filter:(white|black)list:[^]]+|http(:\/\/[^]]+)?)>/
syn match   confInputs /\v<^(host(_regex|_segment)?|index(es)?|source(type)?|queue|_(raw|meta|time|(TCP|SYSLOG|INDEX_AND_FORWARD)_ROUTING|rcvbuf))>/
syn match   confInputs /\v<^((_)?(white|black)list(\d+)?|crcSalt|initCrcLength|ignoreOlderThan|followTail|alwaysOpenFile|time_before_close)>/
syn match   confInputs /\v<^(multiline_event_extra_waittime|recursive|followSymlink|move_policy|connection_host|(persistentQ|q)?ueueSize)>/
syn match   confInputs /\v<^(requireHeader|listenOnIPv6|acceptFrom|rawTcpDoneTimeout|route|enableS2SHeartbeat|(s2sHeartbeat|inputShutdown)Timeout)>/
syn match   confInputs /\v<^(stopAcceptorAfterQBlock|negotiate(ProtocolLevel|NewProtocol)|concurrentChannelLimit|compressed|token|stats)>/
syn match   confInputs /\v<^(serverCert|requireClientCert|cipherSuite|ecdhCurve(s|Name)|dh(F|f)ile|allow(Ssl(Renegotiation|Compression)|QueryStringAuth))>/
syn match   confInputs /\v<^(ssl(Password|Versions|QuietShutdown|(Alt|Common)NameToCheck|Keysfile(Password)?)|password|rootCA|supportSSLV3Only)>/
syn match   confInputs /\v<^(no_(priority_stripping|appending_timestamp)|interval|passAuth|send_index_as_argument_for_path|start(_by_shell|_from|ingNode))>/
syn match   confInputs /\v<^(signedaudit|filters|recurse|followLinks|pollPeriod|(hash|sendEvent)MaxSize|fullEvent|filesPerDelay|delayInMills)>/
syn match   confInputs /\v<^(regex\d+|port|disabled|outputgroup|use(Ack|DeploymentServer|EnglishOnly|_old_eventlog_api|_threads|r(BufferSize)?))>/
syn match   confInputs /\v<^(enableSSL|dedicatedIoThreads|replyHeader\.\w+|max(Sockets|Threads|IdleTime))>/
syn match   confInputs /\v<^((busyK|k)eepAliveIdleTimeout|ca(CertFile|Path)|crossOriginSharingPolicy|forceHttp10|sendStrictTransportSecurityHeader)>/
syn match   confInputs /\v<^(ackIdleCleanup|channel_cookie|description|addressFamily|baseline(_interval)?|batch_size|(checkpoint|read|sampling)Interval)>/
syn match   confInputs /\v<^(counters|current_only|direction|driverBufferSize|formatString|hive|instances|mode|monitorSubtree|object|packetType)>/
syn match   confInputs /\v<^(evt_((ad|sid)_cache_(disabled|exp(_neg)?|max_entries)|(dc|dns)_name|resolve_ad_(ds|obj))|multikvMax(EventCount|TimeMs))>/
syn match   confInputs /\v<^(printSchema|pro(c(ess)?|tocol)|remoteAddress|renderXml|schedule|script|showZeroValue|sid_cache_(disabled|exp(_neg)?|max_entries))>/
syn match   confInputs /\v<^(suppress_(checkpoint|keywords|opcode|sourcename|task|text|type)|targetDc|thread_wait_time_msec|type)>/

syn match   confInputsConstants /\v<((parsing|index)Queue|auto|never|always|yes|no|only|(proxied_)?ip|dns|none|PDC|single|multikv|sinkhole)$>/
syn match   confInputsconstants /\v<(connect|accept|transport|tcp|udp|has_key|absent_key:[^:]+:[^\ |\=]+|ipv(4|6)|(in|out)bound)$>/
syn match   confInputsConstants /\v<(average|count|dev|min|max)$>/

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
hi def link confInputsStanzas Identifier
hi def link confInputs Keyword
hi def link confInputsConstants Constant
