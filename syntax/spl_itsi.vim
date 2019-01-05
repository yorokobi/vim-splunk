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
syn cluster confStanzas contains=confGenericStanzas

"
" ITSI-specific configs
"

" ITSI app_permissions.conf
syn match   ITSI_App_Permissions /\v<^(capabilities|description|display_name|messages|metadata)>/

" ITSI deep_dive_drilldowns.conf
syn match   ITSI_DeepDiveDrilldowns /\v<^(type|replace_tokens|search|add_lane_enabled|use_bucket_timerange|new_lane_settings|uri(_payload_type)?)>/
syn match   ITSI_DeepDiveDrilldowns /\v<^(entity_(level_only|tokens|activation_rules))>/
syn match   ITSI_DeepDiveDrilldowns /\v<^((metric|kpi|event)_lane_enabled)>/

" ITSI drawing_elements.conf
syn match   ITSI_DrawingElements /\v<^(bgColor|color|stroke|height|width|vizType|context_id|searchSource|threshold_eval|use_percentage|isThresholdEnabled)>/
syn match   ITSI_DrawingElements /\v<^(font(Size|Family|Color))>/
syn match   ITSI_DrawingElements /\v<^((start|end)PointDecoratorType)>/
syn match   ITSI_DrawingElements /\v<^(label(Val|Flag))>/
syn match   ITSI_DrawingElements /\v<^(threshold_(field|comparator|values|labels))>/
syn match   ITSI_DrawingElements /\v<^(dataModel(Specification|StatOp|WhereClause))>/
syn match   ITSI_DrawingElements /\v<^(gauge_(thresholds|colors))>/
syn match   ITSI_DrawingElements /\v<^(default(Height|Width))>/
syn match   ITSI_DrawingElements /\v<^(search_(aggregate|time_series_aggregate|alert_earliest))>/
syn match   ITSI_DrawingElements /\v<^(use(CustomDrilldown|KpiSearchAlertEarliest))>/

syn match   ITSI_DrawingElements_Constants /\v<(none|simple|triangle)$>/

" ITSI drilldownsearch_offset.conf
syn match   ITSI_DrillDownSearch_Offset /\v<^(timeInSecs)>/
syn match   ITSI_DrillDownSearch_Offset /\v<^((earliest_|latest_)?description)>/

" ITSI itsi_da.conf
syn match   ITSI_da /\v<^(description|saved_search|title|title(_field)?)>/
syn match   ITSI_da /\v<^((description|identifier|informational)_fields)>/
syn match   ITSI_da /\v<^(entity_(source_templates|rules))>/
syn match   ITSI_da /\v<^((recommended|informational|optional)_kpis)>/

" ITSI itsi_deep_dive.conf
syn match   ITSI_DeepDive /\v<^(focus_id|title|lane_settings_collection|acl|mod_time)>/
syn match   ITSI_DeepDive /\v<^(description|is_named|_owner|source_itsi_da)>/

" ITSI itsi_glass_table.conf
syn match   ITSI_GlassTable /\v<^(latest|earliest|title|description|mod_time|acl|_owner|source_itsi_da)>/
syn match   ITSI_GlassTable /\v<^(svg_(content|coordinates))>/

" ITSI itsi_kpi_template.conf
syn match   ITSI_KPI_Template /\v<^(description|title|_owner|kpis|source_itsi_da)>/

" ITSI itsi_module_vis.conf
syn match   ITSI_ModuleVis /\v<^(list|control_token|title|extendable_tab|activation_rule)>/
syn match   ITSI_ModuleVis /\v<^(row\.\d+)>/

" ITSI itsi_notable_event_retention.conf
syn match   ITSI_Notable_Event_Retention /\v<^(retentionTimeInSec|disabled)>/

" ITSI itsi_notable_event_severity.conf
syn match   ITSI_Notable_Event_Severity /\v<^(color|lightcolor|label|default)>/

" ITSI itsi_notable_event_status.conf
syn match   ITSI_Notable_Event_Status /\v<^(label|default|description|end)>/

" ITSI itsi_service.conf
syn match   ITSI_Services /\v<^(description|title|_owner|tags|kpis|entity_rules)>/
syn match   ITSI_Services /\v<^(identifying_name|mod_source|source_itsi_da)>/
syn match   ITSI_Services /\v<^(services_depend(s_on|ing_on_me))>/

" ITSI itsi_settings.conf
syn match   ITSI_Settings /\v<^(show_migration_message)>/

" ITSI managed_configurations.conf
syn match   ITSI_Managed_Configurations /\v<^(disabled|endpoint|label|description|class|link|lookup_type)>/
syn match   ITSI_Managed_Configurations /\v<^(editable(_on_shc)?)>/
syn match   ITSI_Managed_Configurations /\v<^(attribute(_type)?)>/
syn match   ITSI_Managed_Configurations /\v<^((sav|guid)edsearch)>/

" ITSI notable_event_actions.conf
syn match   ITSI_Notable_Event_Actions /\v<^(disabled)>/

" ITSI postprocess.conf
syn match   ITSI_PostProcess /\v<^(disabled|savedsearch|postprocess)>/

" ITSI service_analyzer_settings.conf
syn match   ITSI_Service_Analyzer_Settings /\v<^(ftr_override)>/

" ITSI threshold_labels.conf
syn match   ITSI_Threshold_Labels /\v<^(color|lightcolor|threshold_level)>/
syn match   ITSI_Threshold_Labels /\v<^(health_(weight|m(in|ax)))>/

" ITSI threshold_periods.conf
syn match   ITSI_Threshold_Periods /\v<^(past|description|relative)>/

" ITSI
hi def link ITSI_AlertActions Keyword
hi def link ITSI_App_Permissions Keyword
hi def link ITSI_DeepDiveDrilldowns Keyword
hi def link ITSI_DrawingElements Keyword
hi def link ITSI_DrawingElements_Constants Constant
hi def link ITSI_DrillDownSearch_Offset Keyword
hi def link ITSI_Inputs Keyword
hi def link ITSI_Inputs_Constants Constant
hi def link ITSI_da Keyword
hi def link ITSI_DeepDive Keyword
hi def link ITSI_GlassTable Keyword
hi def link ITSI_KPI_Template Keyword
hi def link ITSI_ModuleVis Keyword
hi def link ITSI_Notable_Event_Retention Keyword
hi def link ITSI_Notable_Event_Severity Keyword
hi def link ITSI_Notable_Event_Status Keyword
hi def link ITSI_Services Keyword
hi def link ITSI_Settings Keyword
hi def link ITSI_Managed_Configurations Keyword
hi def link ITSI_Notable_Event_Actions Keyword
hi def link ITSI_PostProcess Keyword
hi def link ITSI_SavedSearches Keyword
hi def link ITSI_SavedSearches_Constants Constant
hi def link ITSI_Service_Analyzer_Settings Keyword
hi def link ITSI_Threshold_Labels Keyword
hi def link ITSI_Threshold_Periods Keyword
