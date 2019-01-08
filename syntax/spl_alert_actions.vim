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
syn cluster confStanzas contains=confAlertActionsStanzas,confGenericStanzas

" alert_actions.conf
syn match   confAlertActionsStanzas contained /\v<(default|email|rss|script|summary_index|(populate_)?lookup)>/
syn match   confAlertActions /\v<^(max(results|time)|hostname|ttl|track_alert|command)>/
syn match   confAlertActions /\v<^(from|to|(b)?cc|subject|format|inline)>/
syn match   confAlertActions /\v<^(send(results|csv|pdf)|useNSSubject|mailserver|append|pdfview)>/
syn match   confAlertActions /\v<^(width_sort_columns|preprocess_results|items_count|filename|_name|dest)>/
syn match   confAlertActions /\v<^(priority|inline|is_custom|payload_format|icon_path|content_type)>/
syn match   confAlertActions /\v<^(use_(ssl|tls)|auth_(username|password))>/ 
syn match   confAlertActions /\v<^(report(Paper(Size|Orientation)|Server(Enabled|URL)|IncludeSplunkLogo|CIDFontList|FileName))>/
syn match   confAlertActions /\v<^(pdf\.(logo_path|html_image_rendering|(footer|header)_(enabled|center|left|right)))>/
syn match   confAlertActions /\v<^(alert\.execute\.cmd(\.arg\.\d+)?|label|description)>/
syn match   confAlertActions /\v<^(subject\.(alert|report)|message\.(report|alert)|footer\.text|include\.((results|view)_link|search|trigger|trigger_time))>/
syn match   confAlertActions /\v<^(cipherSuite|ssl((Alt|Common)NameToCheck|VerifyServerCert|Versions))>/

" 7.2.3
syn match   confAlertActions /\v<^(forceCsvResults)>/

syn match   confAlertActions_Constants /\v<(table|raw|logo|title|timestamp|pagination|none|csv|xml|json|description)$>/
syn match   confAlertActions_Constants /\v<(html|plain|portrait|landscape|letter|legal|ledger|a(2|3|4|5)|auto)$>/

" etc/apps/alert_logevent/README/alert_actions.conf.spec
syn match   confAlertActionsStanzas contained /\v<logevent>/
syn match   confAlertActions /\v<^(param\.(event|host|source(type)?|index))>/

" etc/apps/alert_webhook/README/alert_actions.conf.spec
syn match   confAlertActionsStanzas contained /\v<webhook>/
syn match   confAlertActions /\v<^(param.user_agent)>/

" Splunk_TA_okta
syn match   confAlertActions /\v<^(param\.(action|user_(id|name)|group_(id|name)))>/

" ITSI
syn match   confAlertActions /\v<^(drilldown_(search|uri)|subtitle|delta|in(vert|line)|_name)>/
syn match   confAlertActions /\v<^(param\.(http_token_name|index|sourcetype|event_identifier_fields|search_type|is_use_event_time|host))>/
syn match   confAlertActions /\v<^(param\.(fields|description|protocols|duration|category|limit|verbose))>/
syn match   confAlertActions /\v<^(constraint_(method|fields)|_itsi_(kpi|service)_id)>/
syn match   confAlertActions /\v<^((value|delta)_qual|group\.\d+\.(name|order)|value(_suffix)?)>/

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
hi def link confAlertActionsStanzas Identifier
hi def link confAlertActions_Constants Constant
hi def link confAlertActions Keyword
