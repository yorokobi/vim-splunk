" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" user-prefs.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confUserPrefsStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confUserPrefsStanzas contained /\v<(general_default|role_[^]]+)>/

" Key words
syn match   confUserPrefs /\v<^(datasets:showInstallDialog|dismissedInstrumentationOptInVersion|default_(namespace|(earliest|latest)_time))>/
syn match   confUserPrefs /\v<^(hideInstrumentationOptInModal|tz|lang|install_source_checksum)>/
syn match   confUserPrefs /\v<^(search_(assistant|auto_format|line_numbers|syntax_highlighting|use_advanced_editor))>/
syn match   confUserPrefs /\v<^(render_version_messages|notification_python_3_impact|eai_(app_only|results_per_page))>/
syn match   confUserPrefs /\v<^(checked_new_(maintenance_)?version|new_(maintenance_)?version|appOrder)>/
syn match   confUserPrefs /\v<^(theme|notification_(python_2_removal|noah_upgrade))>/
syn match   confUserPrefs /\v<^(restart_background_jobs|app_bar_cache_timeout_min)>/

" Constants
syn match   confUserPrefsConstants /\v<(full|compact|none|light|dark|black-white|enterprise|default(-|_)system(-|_)theme)$>/
syn match   confUserPrefsConstants /\v<(black\-white)$>/

" Deprecated
syn match   confDeprecated /\v<^(showWhatsNew)>/

" Highlighting
hi def link confUserPrefsStanzas Identifier
hi def link confUserPrefs Keyword
hi def link confUserPrefsConstants Constant
hi def link confDeprecated Removed
