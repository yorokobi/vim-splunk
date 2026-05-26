" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" alert_actions.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confAlertActionsStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confAlertActionsStanzas contained /\v<(email|rss|script|summary_index|(populate_)?lookup)>/
syn match   confAlertActionsStanzas contained /\v<summary_metric_index>/

" Key words
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
syn match   confAlertActions /\v<^(cipherSuite|ssl((Alt|Common)NameToCheck|VerifyServer(Cert|Name)|Versions))>/
syn match   confAlertActions /\v<^(forceCsvResults|sendpng|python\.required)>/
syn match   confAlertActions /\v<^(allowedDomainList|escapeCSVNewline|allow_empty_attachment)>/
syn match   confAlertActions /\v<^(newLineValuesInCSV|oauth_(client_(id|secret)|url|scope))>/
syn match   confAlertActions /\v<^(enable_allowlist|allowlist\.\k+)>/

" Constants
syn match   confAlertActions_Constants /\v<(table|raw|logo|title|timestamp|pagination|none|csv|xml|json)$>/
syn match   confAlertActions_Constants /\v<(html|plain|portrait|landscape|letter|legal|ledger|a(2|3|4|5)|auto)$>/

" etc/apps/alert_logevent/README/alert_actions.conf.spec
syn match   confAlertActionsStanzas contained /\v<logevent>/
syn match   confAlertActions /\v<^(param\.(event|host|source(type)?|index))>/

" etc/apps/alert_webhook/README/alert_actions.conf.spec
syn match   confAlertActionsStanzas contained /\v<webhook>/
syn match   confAlertActions /\v<^(param.user_agent)>/

" Highlighting
hi def link confAlertActionsStanzas Identifier
hi def link confAlertActions_Constants Constant
hi def link confAlertActions Keyword
