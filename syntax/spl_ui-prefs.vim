" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" ui-prefs.conf
" This file is deprecated in 10.4.0.

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confUIPrefsStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
" syn match   confUIPrefsStanzas contained /\v<()>/

" Key words
syn match   confUIPrefs /\v<^(dispatch\.(earliest|latest)_time|countPerPage|display\.general\.enablePreview|display\.statistics\.(rowNumbers|wrap|drilldown))>/
syn match   confUIPrefs /\v<^(display\.prefs\.(autoOpenSearchAssistant|timeline\.(height|minimized|minimalMode)|(acl|app)Filter|listMode|searchContext|events\.count))>/
syn match   confUIPrefs /\v<^(display\.prefs\.(statistics\.count|fieldCoverage|enableMetaData|showDataSummary|customSampleRatio|showSPL|livetail))>/
syn match   confUIPrefs /\v<^(display\.events\.(fields|type|rowNumbers|maxLines|(raw|list|table)\.drilldown|(list|table)\.wrap))>/
syn match   confUIPrefs /\v<^(display\.visualizations\.((custom\.)?type|chartHeight|charting\.(chart(\.(style))?|legend\.labelStyle\.overflowMode)))>/
syn match   confUIPrefs /\v<^(display\.page\.search\.patterns\.sensitivity|display\.page\.home\.showGettingStarted)>/
syn match   confUIPrefs /\v<^(display\.page\.search\.(mode|timeline(\.format|\.scale)|showFields|searchHistory(TimeFilter|Count)))>/

" Constants
syn match   confUIPrefsConstants /\v<(none|app|owner|tiles|table|raw|list|inner|outer|full|row|cell|charting|singlevalue|fast|smart|verbose|compact|hidden)$>/
syn match   confUIPrefsConstants /\v<(line|area|column|bar|pie|scatter|(radial|filler|marker)Gauge|minimal|shiny|ellipsis(End|Middle|Start)|log|linear)$>/

" Highlighting
hi def link confUIPrefsStanzas Identifier
hi def link confUIPrefs Keyword
hi def link confUIPrefsConstants Constant
