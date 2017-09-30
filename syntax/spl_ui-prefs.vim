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
syn cluster confStanzas contains=confUIPrefsStanzas,confGenericStanzas

" ui-prefs.conf
syn match   confUIPrefsStanzas contained /\v<(default)>/

syn match   confUIPrefs /\v<^(dispatch\.(earliest|latest)_time|countPerPage|display\.general\.enablePreview|display\.statistics\.(rowNumbers|wrap|drilldown))>/
syn match   confUIPrefs /\v<^(display\.prefs\.(autoOpenSearchAssistant|timeline\.(height|minimized|minimalMode)|(acl|app)Filter|listMode|searchContext|events\.count))>/
syn match   confUIPrefs /\v<^(display\.prefs\.(statistics\.count|fieldCoverage|enableMetaData|showDataSummary|customSampleRatio|showSPL|livetail))>/
syn match   confUIPrefs /\v<^(display\.events\.(fields|type|rowNumbers|maxLines|(raw|list|table)\.drilldown|(list|table)\.wrap))>/
syn match   confUIPrefs /\v<^(display\.visualizations\.((custom\.)?type|chartHeight|charting\.(chart(\.(style))?|legend\.labelStyle\.overflowMode)))>/
syn match   confUIPrefs /\v<^(display\.page\.search\.patterns\.sensitivity|display\.page\.home\.showGettingStarted)>/
syn match   confUIPrefs /\v<^(display\.page\.search\.(mode|timeline(\.format|\.scale)|showFields|searchHistory(TimeFilter|Count)))>/

syn match   confUIPrefsConstants /\v<(none|app|owner|tiles|table|raw|list|inner|outer|full|row|cell|charting|singlevalue|fast|smart|verbose|compact|hidden)$>/
syn match   confUIPrefsConstants /\v<(line|area|column|bar|pie|scatter|(radial|filler|marker)Gauge|minimal|shiny|ellipsis(End|Middle|Start)|log|linear)$>/

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
hi def link confUIPrefsStanzas Identifier
hi def link confUIPrefs Keyword
hi def link confUIPrefsConstants Constant
