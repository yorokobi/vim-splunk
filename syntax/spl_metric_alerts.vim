" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" metric_alerts.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confMetricsAlertsStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
" syn match   confMetricsAlertsStanzas contained /\v<()>/

" Key words
syn match   confMetricsAlerts /\v<^(description|groupby|filter|metric_indexes|condition)>/
syn match   confMetricsAlerts /\v<^(trigger\.(suppress|expires|max_tracked|prepare|(action|evaluation)_per_group)|label\.\k+|splunk_ui\.\k+|action\.\k+)>/
syn match   confMetricsAlerts /\v<^(trigger\.(threshold))>/

" Constants
syn match   confMetricsAlertsConstants /\v<(always|once|always\ after\ \dm|once\ after\ \dm)$>/

" Highlighting
hi def link confMetricsAlertsStanzas Identifier
hi def link confMetricsAlerts Keyword
hi def link confMetricsAlertsConstants Constant
