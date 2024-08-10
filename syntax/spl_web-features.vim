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
syn cluster confStanzas contains=confWebFeaturesStanzas,confGenericStanzas

" web-features.conf
syn match   confWebFeaturesStanzas contained /\v<(feature:(quarantine_files|dashboard_inputs_localization))>/

syn match   confWebFeatures /\v<^(enable_(jQuery2|unsupported_hotlinked_imports|dashboard_inputs_localization))>/

" 9.1.0
syn match   confWebFeaturesStanzas contained /\v<(feature:(search_(v2_endpoint|auto_format)|dashboard(s_csp|_studio)))>/
syn match   confWebFeaturesStanzas contained /\v<(feature:(highcharts_accessibility|windows_rce|page_migration|share_job|ui_prefs_optimizations))>/

syn match   confWebFeatures /\v<^(enable_(search_v2_endpoint|dashboards_(external_content|redirection)_restriction|inputs_on_canvas|show_hide|events_viz))>/
syn match   confWebFeatures /\v<^(enable_(acuif_pages|(home|triggered_alerts)_vnext|share_job_control|autoformatted_comments))>/
syn match   confWebFeatures /\v<^((internal\.)?dashboards_trusted_domain\.\k+|disable_highcharts_accessibility|optimize_ui_prefs_performance)>/
syn match   confWebFeatures /\v<^()>/

" 9.3.0
syn match   confWebFeaturesStanzas contained /\v<(feature::windows_rce|feature:(splunk_web_optimizations|spotlight_search|appserver))>/
syn match   confWebFeaturesStanzas contained /\v<(feature:(search_sidebar|field_filters|identity_sidecar_scim))>/
syn match   confWebFeatures /\v<^(activate_(dsl_webworkers_for_visualizations|save_report_to_dashboard_studio|source_mode_validation))>/
syn match   confWebFeatures /\v<^(allow_multiple_interactions|show_corner_radius_editor|activate_scheduled_export|execute_chain_searches_with_tokens_in_search_process)>/
syn match   confWebFeatures /\v<^(enable_((datasets|authoverview|password_management_page)_vnext|react_users_page))>/
syn match   confWebFeatures /\v<^(enable_app_bar_(performance_optimizations|caching)|bypass_app_bar_performance_optimizations_apps)>/
syn match   confWebFeatures /\v<^(enable_(spotlight_search|sidebar_preview|field_filters_ui)|enabled|python\.version)>/
syn match   confWebFeaturesConstants /\v<(latest|python3\.(7|9))$>/

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
hi def link confWebFeaturesStanzas Identifier
hi def link confWebFeatures Keyword
hi def link confWebFeaturesConstants Constant
