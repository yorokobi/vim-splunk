augroup filetypedetect
    autocmd BufNewFile,BufRead eventgen.conf,ldap.conf,logging.conf,pdf_server.conf,perfmon.conf,regmon-filters.conf,ssl.conf,tenants.conf,tsidx_retention.conf,app_permissions.conf,deep_dive_drilldowns.conf,drawing_elements.conf,drilldownsearch_offset.conf,itsi_da.conf,itsi_deep_dive.conf,itsi_glass_table.conf,itsi_kpi_template.conf,itsi_module_viz.conf,itsi_notable_event_retention.conf,itsi_notable_event_severity.conf,itsi_notable_event_status.conf,itsi_service.conf,itsi_settings.conf,managed_configurations.conf,notable_event_actions.conf,postprocess.conf,service_analyzer_settings.conf,threshold_labels.conf,threshold_periods.conf,okta.conf,database.conf,healthlog.conf,settings.conf setf splunk
augroup END

" Deprecated by Splunk 6.0+
" Support for Splunk 5.x (and earlier) expired 30 Nov 2017
" http://docs.splunk.com/Documentation/Splunk/6.0/Installation/Aboutupgradingto6.0READTHISFIRST
augroup filetypedetect
    autocmd BufNewFile,BufRead admon.conf setf spl_admon
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead alert_actions.conf setf spl_alert_actions
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead app.conf setf spl_app
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead audit.conf setf spl_audit
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead authentication.conf setf spl_authentication
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead authorize.conf setf spl_authorize
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead bookmarks.conf setf spl_bookmarks
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead collections.conf setf spl_collections
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead commands.conf setf spl_commands
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead datamodels.conf setf spl_datamodels
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead datatypesbnf.conf setf spl_datatypesbnf
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead default-mode.conf setf spl_default-mode
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead deploymentclient.conf setf spl_deploymentclient
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead distsearch.conf setf spl_distsearch
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead event_renderers.conf setf spl_event_renderers
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead eventdiscoverer.conf setf spl_eventdiscoverer
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead eventtypes.conf setf spl_eventtypes
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead federated.conf setf spl_federated
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead fshpasswords.conf setf spl_fshpasswords
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead fields.conf setf spl_fields
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead health.conf setf spl_health
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead indexes.conf setf spl_indexes
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead inputs.conf setf spl_inputs
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead limits.conf setf spl_limits
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead literals.conf setf spl_literals
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead livetail.conf setf spl_livetail
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead macros.conf setf spl_macros
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead messages.conf setf spl_messages
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead metric_alerts.conf setf spl_metric_alerts
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead metric_rollups.conf setf spl_metric_rollups
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead multikv.conf setf spl_multikv
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead outputs.conf setf spl_outputs
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead passwords.conf setf spl_passwords
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead procmon-filters.conf setf spl_procmon-filters
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead props.conf setf spl_props
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead pubsub.conf setf spl_pubsub
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead restmap.conf setf spl_restmap
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead savedsearches.conf setf spl_savedsearches
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead searchbnf.conf setf spl_searchbnf
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead segmenters.conf setf spl_segmenters
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead server.conf setf spl_server
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead serverclass.conf setf spl_serverclass
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead source-classifier.conf setf spl_source-classifier
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead sourcetypes.conf setf spl_sourcetypes
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead splunk-launch.conf setf spl_splunk-launch
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead tags.conf setf spl_tags
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead times.conf setf spl_times
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead transactiontypes.conf setf spl_transactiontypes
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead transforms.conf setf spl_transforms
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead ui-prefs.conf setf spl_ui-prefs
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead ui-tour.conf setf spl_ui-tour
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead user-prefs.conf setf spl_user-prefs
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead user-seed.conf setf spl_user-seed
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead viewstates.conf setf spl_viewstates
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead visualizations.conf setf spl_visualizations
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead web.conf setf spl_web
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead wmi.conf setf spl_wmi
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead workflow_actions.conf setf spl_workflow_actions
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead workload_pools.conf setf spl_workload_pools
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead workload_rules.conf setf spl_workload_rules
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead splunk_monitoring_console_assets.conf setf spl_monitoring_console_assets
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead checklist.conf setf spl_checklist
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead dmc_alerts.conf setf spl_dmc_alerts
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead launcher.conf setf spl_launcher
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead instance.cfg setf spl_instance_cfg
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead crawl.conf setf spl_crawl
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead default.meta,local.meta setf spl_dotmeta
augroup END

augroup filetypedetect
    autocmd BufNewFile,BufRead telemetry.conf setf spl_telemetry
augroup END

" Splunk Machine Learning Toolkit 2.4.0
augroup filetypedetect
    autocmd BufNewFile,BufRead algos.conf setf spl_algos
augroup END
augroup filetypedetect
    autocmd BufNewFile,BufRead mlspl.conf setf spl_mlspl
augroup END

" Splunk DB Connect 3.1.1
augroup filetypedetect
    autocmd BufNewFile,BufRead db_connections.conf setf spl_db_connections
augroup END
augroup filetypedetect
    autocmd BufNewFile,BufRead db_connection_types.conf setf spl_db_connection_types
augroup END
augroup filetypedetect
    autocmd BufNewFile,BufRead db_input_templates.conf setf spl_db_input_templates
augroup END
augroup filetypedetect
    autocmd BufNewFile,BufRead db_inputs.conf setf spl_db_inputs
augroup END
augroup filetypedetect
    autocmd BufNewFile,BufRead db_lookups.conf setf spl_db_lookups
augroup END
augroup filetypedetect
    autocmd BufNewFile,BufRead db_outputs.conf setf spl_db_outputs
augroup END
augroup filetypedetect
    autocmd BufNewFile,BufRead app-migration.conf setf spl_db_app-migration
augroup END
augroup filetypedetect
    autocmd BufNewFile,BufRead identities.conf setf spl_db_identities
augroup END
augroup filetypedetect
    autocmd BufNewFile,BufRead ui-metrics-collector.conf setf spl_db_ui-metrics-collector
augroup END
augroup filetypedetect
    autocmd BufNewFile,BufRead dbx_settings.conf setf spl_db_dbx_settings
augroup END

