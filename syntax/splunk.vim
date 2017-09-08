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
syn match confSpecComment /^\s*\*.*/ contains=confTodo oneline display

syn region confString start=/"/ skip="\\\"" end=/"/ oneline display contains=confNumber,confVar
syn region confString start=/`/             end=/`/ oneline display contains=confNumber,confVar
syn region confString start=/'/ skip="\\'"  end=/'/ oneline display contains=confNumber,confVar
syn match  confNumber /\v[+-]?\d+([ywdhsm]|m(on|ins?))(\@([ywdhs]|m(on|ins?))\d*)?>/
syn match  confNumber /\v[+-]?\d+(\.\d+)*>/
syn match  confNumber /\v<\d+[TGMK]B>/
syn match  confPath   ,\v(^|\s|\=)\zs(file:|https?:|\$\k+)?(/+\k+)+(:\d+)?,
syn match  confPath   ,\v(^|\s|\=)\zsvolume:\k+(/+\k+)+,
syn match  confVar    /\$\k\+\$/

syn keyword confBoolean on off t[rue] f[alse] T[rue] F[alse]
syn keyword confTodo FIXME NOTE TODO contained

" Define stanzas
syn region confStanza matchgroup=confStanzaStart start=/^\[/ matchgroup=confStanzaEnd end=/\]/ oneline transparent contains=@confStanzas

" Group clusters
syn cluster confStanzas contains=confCrawlStanzas,confEventGenStanzas,confSALDAPStanzas,confSALDAPLoggingStanzas,confSALDAPSSLStanzas,confPDFserverStanzas,confRegmonFiltersStanzas,confTenantsStanzas,confGenericStanzas,confMetaStanzas,confInstanceStanzas

syn match confGenericStanzas display contained /\v[^\]]+/

" crawl.conf
syn match   confCrawlStanzas contained /\v<(default|files|network)>/
syn keyword confCrawl collapse_threshold big_dir_filecount index max_badfiles_per_dir
syn keyword confCrawl host subnet root
syn match   confCrawl /\v<bad_(directories|extensions|file_matches)_list>/
syn match   confCrawl /\v<(packed_extensions|days_sizek_pairs)_list>/

" eventgen.conf
syn match   confEventGenStanzas contained /\v<(default|global)>/
syn keyword confEventGen spoolDir spoolFile interval count earliest latest breaker token 
syn keyword confEventGen replacement replacementType outputMode maxIntervalsBeforeFlush
syn match   confEventGen /\v<token\.\d+\.(token|replacement(Type)?)>/
syn match   confEventGen /\v<splunk(Host|User|Pass)>/

" instance.cfg
syn match   confInstanceStanzas contained /\v<general>/
syn keyword confInstance guid

" ldap.conf from SA-ldapsearch
syn match   confSALDAPStanzas contained /\v<default>/
syn keyword confSALDAP alternatedomain basedn server ssl port binddn password decode paged_size

" logging.conf from SA-ldapsearch
syn match   confSALDAPLoggingStanzas contained /\v<loggers|logger_root|handlers|formatters|handler_(\S+)|formatter_(\S+)>/
syn keyword confSALDAPLogging keys level handlers qualname propagate args class formatter datefmt format
syn keyword confSALDAPLogging_Constants critical error warning info debug notset

" ssl.conf from SA-ldapsearch
syn match   confSALDAPSSLStanzas contained /\v<sslConfig>/
syn keyword confSALDAPSSL sslVersions sslVerifyServerCert caCertFile caPath

" *.meta
syn match confMetaStanzas contained /\v<(views(\/[^\]]+)?|transforms|exports|savedsearches|macros|eventtypes)>/
syn match confMeta /\v<^(access|export|owner)>/
syn match confMeta_Constants /\v<(system|admin|power|read|write none)$>/

" pdf_server.conf
syn match   confPDFserverStanzas contained /\v<(settings)>/
syn match   confPDFserver /\v<^((appserver|client)_ipaddr|startwebserver|httpport|enableSplunkWebSSL|supportSSLV3Only|static_dir|enable_gzip|screenshot_enabled)>/
syn match   confPDFserver /\v<^((caCert|privKey)Path|request\.show_tracebacks|engine\.autoreload_on|response\.timeout|pid_path|firefox_cmbline|Xvfb|xauth|mcookie)>/
syn match   confPDFserver /\v<^(log\.(screen|(access|error)_file)|max_(concurrent|queue)|server\.(socket_host|thread_pool))>/
syn match   confPDFserver /\v<^((static|root)_endpoint|tools\.(sessions\.(on|timeout|storage_(type|path))|decode\.on|encode\.(on|encoding)))>/

" regmon-filters.conf
syn match   confRegmonFiltersStanzas contained /\v<(default)>/
syn match   confRegmonFilters /\v<^(proc|hive|type|baseline(_interval)?|disabled|index)>/

" telemetry.conf
syn match   confTelemetry /\v<^(showOptInModal|deprecatedConfig|retryTransaction|optInVersion(Acknowledged)?|sendAnonymizedWebAnalytics|deploymentID|swaEndpoint)>/
syn match   confTelemetry /\v<^(send(License|Anonymized)Usage|precheckSend(License|Anonymized)Usage|telemetrySalt)>/

" tenants.conf
syn match   confTenantsStanzas contained /\v<(default|tenant:[^\]]+)>/
syn match   confTenants /\v<^(filterType|(black|white)list\.|phoneHomeTopic)>/

"================================================
" splunk_app_db_connect
"================================================

" app-migration.conf
syn match   confAppMigration /\v<^(STATE|DEST_CONF)>/

" db_connections.conf
syn match   confDBConnections /\v<^(serviceClass|testQuery|database|connection_type|identity|isolation_level|readonly|username|password|host|port)>/
syn match   confDBConnections /\v<^(enable_query_wrapping|cwallet_location|sslConnectionType|oracle_cipher_suites|informixserver|useConnectionPool|fetch_size)>/
syn match   confDBConnections /\v<^(max((Idle|Total)Conn|(ConnLifetime|Wait)Millis|customizedJdbcUrl))>/
syn match   confDBConnections /\v<^(jdbc(Url(SSL)?Format|UseSSL|DriverClass))>/

" db_connection_types.conf
syn match   confDBConnectionTypes /\v<^(serviceClass|displayName|database|port|useConnectionPool|cwallet_location|sslConnectionType|oracle_cipher_suites)>/
syn match   confDBConnectionTypes /\v<^(ui_default_(catalog|schema|connection_properties))>/
syn match   confDBConnectionTypes /\v<^(supported(Major|Minor)?Version(s)?|jdbc(Url(SSL)?Format|UseSSL|DriverClass)|max((Idle|Total)Conn|(ConnLifetime|Wait)Millis))>/

" db_inputs.conf
syn match   confDBInputs /\v<^(batch_upload_size)>/
syn match   confDBInputsConstants /\v<(batch|advanced)$>/

" db_lookups.conf
" TODO: grab the relevant bits for this file and place them here rather
" than let them live in other confXXX settings.

" db_outputs.conf
syn match   confDBOutputs /\v<^(using_upsert|unique_key)>/

" dbx_logging.conf
syn match   confDBXLogging /\v<^(keys|level|handlers|propagate|qualname|class|formatter|args)>/

" dbx_settings.conf
syn match   confDBXSettings /\v<^(db(xquery|xoutput|xlookup|(in|out)put)|connector)>/

" settings.conf
syn match   confSettings /\v<^(interval_\S+|java_home|jvm_options|app_id|mode|interval_system)>/

" ui-metrics-collector.conf
syn match   confUIMetricsCollector /\v<^(mode)>/

" healthlog.conf
syn match   confHealthlog /\v<^(hiddens|loggers)>/

" identities.conf
syn match   confIdentities /\v<^((user|domain_)name|password|use_win_auth)>/

" Splunk_TA_f5-bigip
syn match   confInputs /\v<^(nothing)>/

" Splunk_TA_ibm-was
syn match   confInputs /\v<^(was_data_input)>/

"
" ITSI-specific configs
"

" ITSI app_permissions.conf
syn keyword ITSI_App_Permissions capabilities description display_name messages metadata

" ITSI deep_dive_drilldowns.conf
syn keyword ITSI_DeepDiveDrilldowns type replace_tokens search add_lane_enabled use_bucket_timerange new_lane_settings uri uri_payload_type
syn match   ITSI_DeepDiveDrilldowns /\v<entity_(level_only|tokens|activation_rules)>/
syn match   ITSI_DeepDiveDrilldowns /\v<(metric|kpi|event)_lane_enabled>/

" ITSI drawing_elements.conf
syn keyword ITSI_DrawingElements bgColor color stroke height width vizType context_id searchSource threshold_eval use_percentage isThresholdEnabled
syn match   ITSI_DrawingElements /\v<font(Size|Family|Color)>/
syn match   ITSI_DrawingElements /\v<(start|end)PointDecoratorType>/
syn match   ITSI_DrawingElements /\v<label(Val|Flag)>/
syn match   ITSI_DrawingElements /\v<threshold_(field|comparator|values|labels)>/
syn match   ITSI_DrawingElements /\v<dataModel(Specification|StatOp|WhereClause)>/
syn match   ITSI_DrawingElements /\v<gauge_(thresholds|colors)>/
syn match   ITSI_DrawingElements /\v<default(Height|Width)>/
syn match   ITSI_DrawingElements /\v<search_(aggregate|time_series_aggregate|alert_earliest)>/
syn match   ITSI_DrawingElements /\v<use(CustomDrilldown|KpiSearchAlertEarliest)>/

syn keyword ITSI_DrawingElements_Constants none simple triangle

" ITSI drilldownsearch_offset.conf
syn keyword ITSI_DrillDownSearch_Offset timeInSecs
syn match   ITSI_DrillDownSearch_Offset /\v<(earliest_|latest_)?description>/

" ITSI itsi_da.conf
syn keyword ITSI_da description saved_search title
syn match   ITSI_da /\v<title(_field)?>/
syn match   ITSI_da /\v<(description|identifier|informational)_fields>/
syn match   ITSI_da /\v<entity_(source_templates|rules)>/
syn match   ITSI_da /\v<(recommended|informational|optional)_kpis>/

" ITSI itsi_deep_dive.conf
syn keyword ITSI_DeepDive focus_id title lane_settings_collection acl mod_time
syn keyword ITSI_DeepDive description is_named _owner source_itsi_da

" ITSI itsi_glass_table.conf
syn keyword ITSI_GlassTable latest earliest title description mod_time acl _owner source_itsi_da
syn match   ITSI_GlassTable /\v<svg_(content|coordinates)>/

" ITSI itsi_kpi_template.conf
syn keyword ITSI_KPI_Template description title _owner kpis source_itsi_da

" ITSI itsi_module_vis.conf
syn keyword ITSI_ModuleVis list control_token title extendable_tab activation_rule
syn match   ITSI_ModuleVis /\v<row\.\d+>/

" ITSI itsi_notable_event_retention.conf
syn keyword ITSI_Notable_Event_Retention retentionTimeInSec disabled

" ITSI itsi_notable_event_severity.conf
syn keyword ITSI_Notable_Event_Severity color lightcolor label default

" ITSI itsi_notable_event_status.conf
syn keyword ITSI_Notable_Event_Status label default description end

" ITSI itsi_service.conf
syn keyword ITSI_Services description title _owner tags kpis entity_rules
syn keyword ITSI_Services identifying_name mod_source source_itsi_da
syn match   ITSI_Services /\v<services_depend(s_on|ing_on_me)>/

" ITSI itsi_settings.conf
syn keyword ITSI_Settings show_migration_message

" ITSI managed_configurations.conf
syn keyword ITSI_Managed_Configurations disabled endpoint label description class link lookup_type
syn match   ITSI_Managed_Configurations /\v<editable(_on_shc)?>/
syn match   ITSI_Managed_Configurations /\v<attribute(_type)?>/
syn match   ITSI_Managed_Configurations /\v<(sav|guid)edsearch>/

" ITSI notable_event_actions.conf
syn keyword ITSI_Notable_Event_Actions disabled

" ITSI postprocess.conf
syn keyword ITSI_PostProcess disabled savedsearch postprocess

" ITSI service_analyzer_settings.conf
syn keyword ITSI_Service_Analyzer_Settings ftr_override

" ITSI threshold_labels.conf
syn keyword ITSI_Threshold_Labels color lightcolor threshold_level
syn match   ITSI_Threshold_Labels /\v<health_(weight|m(in|ax))>/

" ITSI threshold_periods.conf
syn keyword ITSI_Threshold_Periods past description relative

" Machine Learning Toolkit
syn match   mltkMlspl /\v<^(use_sampling|handle_new_cat|streaming_apply|max_(inputs|fit_time|(memory_usage|model_size)_mb)|summary_(depth_limit|return_json))>/

" Splunk_TA_okta
" okta.conf
syn match   oktaOkta /\v<^(proxy_(enabled|type|rdns|url|port|username|password)|okta_server_(url|token)|loglevel|custom_cmd_enabled)>/

"
" Splunk_TA_oracle
"
" database.conf
syn match   oracleDatabase /\v<^(database|host|username|password|isolation_level|port|readonly|type|disabled)>/

" Highlight definitions (generic)
hi def link confComment Comment
hi def link confSpecComment Comment
hi def link confBoolean Boolean
hi def link confTodo Todo

" Other highlights
hi def link confString String
hi def link confNumber Number
hi def link confPath   Number
hi def link confVar    PreProc

hi def link confStanzaStart Delimiter
hi def link confstanzaEnd Delimiter

" Highlight for stanzas
hi def link confStanza Function
hi def link confGenericStanzas Function
hi def link confAlertActionsStanzas Identifier
hi def link confAppStanzas Identifier
hi def link confAuditStanzas Identifier
hi def link confAuthenticationStanzas Identifier
hi def link confAuthorizeStanzas Identifier
hi def link confChecklistStanzas Identifier
hi def link confCollectionsStanzas Identifier
hi def link confCommandsStanzas Identifier
hi def link confCrawlStanzas Identifier
hi def link confDataModelsStanzas Identifier
hi def link confDataTypesbnfStanzas Identifier
hi def link confDefmodeStanzas Identifier
hi def link confDeployClientStanzas Identifier
hi def link confDistSearchStanzas Identifier
hi def link confDMCAlertsStanzas Identifier
hi def link confEventDiscoverStanzas Identifier
hi def link confEventGenStanzas Identifier
hi def link confEventRenderStanzas Identifier
hi def link confEventTypesStanzas Identifier
hi def link confFieldsStanzas Identifier
hi def link confIndexesStanzas Identifier
hi def link confInputsStanzas Identifier
hi def link confInstanceStanzas Identifier
hi def link confLimitsStanzas Identifier
hi def link confLivetailStanzas Identifier
hi def link confLauncherStanzas Identifier
hi def link confSALDAPStanzas Identifier
hi def link confSALDAPSSLStanzas Identifier
hi def link confSALDAPLoggingStanzas Identifier
hi def link confMetaStanzas Identifier
hi def link confOutputsStanzas Identifier
hi def link confPasswordsStanzas Identifier
hi def link confPDFserverStanzas Identifier
hi def link confPropsStanzas Identifier
hi def link confPubsubStanzas Identifier
hi def link confRegmonFiltersStanzas Identifier
hi def link confRestmapStanzas Identifier
hi def link confSavedSearchesStanzas Identifier
hi def link confSegmenterStanzas Identifier
hi def link confServerClassStanzas Identifier
hi def link confServerStanzas Identifier
hi def link confSourceTypesStanzas Identifier
hi def link confMCAssetsStanzas Identifier
hi def link confTenantsStanzas Identifier
hi def link confTimesStanzas Identifier
hi def link confTransactionTypesStanzas Identifier
hi def link confTransformsStanzas Identifier
hi def link confUIPrefsStanzas Identifier
hi def link confUIToursStanzas Identifier
hi def link confUserPrefsStanzas Identifier
hi def link confUserSeedStanzas Identifier
hi def link confViewStatesStanzas Identifier
hi def link confWebStanzas Identifier
hi def link confWmiStanzas Identifier
hi def link confWorkflowActionsStanzas Identifier
hi def link confSearchbnfStanzas Identifier

" Highlight definitions (by .conf)
hi def link confADmon Keyword
hi def link confAlertActions Keyword
hi def link confAlertActions_Constants Constant
hi def link confApp Keyword
hi def link confApp_Constants Constant
hi def link confAudit Keyword
hi def link confAuthentication Keyword
hi def link confAuthentication_Constants Constant
hi def link confAuthorize Keyword
hi def link confAuthorizeCaps Underlined
hi def link confChecklist Keyword
hi def link confCollections Keyword
hi def link confCollections_Constants Constant
hi def link confCommands Keyword
hi def link confCommands_Constants Constant
hi def link confCrawl Keyword
hi def link confDataTypesbnf Keyword
hi def link confDataModels Keyword
hi def link confDataModelsConstants Constant
hi def link confDefmode Keyword
hi def link confDeployClient Keyword
hi def link confDeployClient_Constants Constant
hi def link confDistSearch Keyword
hi def link confDistSearchConstants Constant
hi def link confDMCAlerts Keyword
hi def link confEventRender Keyword
hi def link confEventDiscover Keyword
hi def link confEventGen Keyword
hi def link confEventTypes Keyword
hi def link confFields Keyword
hi def link confIndexes Keyword
hi def link confIndexes_Constants Constant
hi def link confInputs Keyword
hi def link confInputs_Constants Constant
hi def link confInstance Keyword
hi def link confLauncher Keyword
hi def link confSALDAP Keyword
hi def link confSALDAPLogging Keyword
hi def link confSALDAPLogging_Constants Constant
hi def link confSALDAPSSL Keyword
hi def link confLimits Keyword
hi def link confLimits_Constants Constant
hi def link confLivetail Keyword
hi def link confLivetail_Constants Constant
hi def link confMeta Keyword
hi def link confMeta_Constants Constant
hi def link confMacros Keyword
hi def link confMessages Keyword
hi def link confMessagesConstants Constant
hi def link confMultikv Keyword
hi def link confOutputs Keyword
hi def link confOutputs_Constants Constant
hi def link confPasswords Keyword
hi def link confPDFserver Keyword
hi def link confProcmonFilters Keyword
hi def link confProps Keyword
hi def link confProps_Constants Constant
hi def link confComplex Preproc
hi def link confPubsub Keyword
hi def link confPubsub_Constants Constant
hi def link confRegmonFilters Keyword
hi def link confRestmap Keyword
hi def link confSavedSearches Keyword
hi def link confSavedSearches_Constants Constant
hi def link confSearchbnf Keyword
hi def link confSearchbnf_Constants Constant
hi def link confSegmenters Keyword
hi def link confServer Keyword
hi def link confServer_Constants Constant
hi def link confServerClass Keyword
hi def link confSourceClass Keyword
hi def link confSourceTypes Keyword
hi def link confSplunkLaunch Keyword
hi def link confMCAssets Keyword
hi def link confTags Keyword
hi def link confTelemetry Keyword
hi def link confTenants Keyword
hi def link confTimes Keyword
hi def link confTransactionTypes Keyword
hi def link confTransforms Keyword
hi def link confTransforms_Constants Constant
hi def link confUIPrefs Keyword
hi def link confUIPrefs_Constants Constant
hi def link confUITour Keyword
hi def link confUITour_Constants Constant
hi def link confUserPrefs Keyword
hi def link confUserSeed Keyword
hi def link confViewStates Keyword
hi def link confVisualizations Keyword
hi def link confWeb Keyword
hi def link confWeb_Constants Constant
hi def link confWmi Keyword
hi def link confWorkflowActions Keyword

" splunk_app_db_connect
hi def link confAppMigration Keyword
hi def link confDBConnections Keyword
hi def link confDBConnectionTypes Keyword
hi def link confDBInputs Keyword
hi def link confDBInputsConstants Constant
hi def link confDBOutputs Keyword
hi def link confDBXLogging Keyword
hi def link confDBXSettings Keyword
hi def link confSettings Keyword
hi def link confUIMetricsCollector Keyword
hi def link confHealthlog Keyword
hi def link confIdentities Keyword

" TA_Azure
hi def link AzureInputs Keyword

" Splunk_TA_f5
hi def link f5BigIPInputs Keyword

" Splunk_TA_ibm-was
hi def link IBM_WASInputs Keyword

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

" JMX Add-on
hi def link jmxInputs Keyword
hi def link jmxInputs_Constants Constant

" Machine Learning Toolkit
hi def link mltkMlspl Keyword

" Splunk_TA_okta
hi def link oktaAlertActions Keyword
hi def link oktaInputs Keyword
hi def link oktaOkta Keyword

" Splunk_TA_oracle
hi def link oracleDatabase Keyword
