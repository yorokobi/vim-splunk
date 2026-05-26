" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" web-features.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confWebFeaturesStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confWebFeaturesStanzas contained /\v<(feature:(quarantine_files|dashboard_inputs_localization))>/
syn match   confWebFeaturesStanzas contained /\v<(feature:(search_(v2_endpoint|auto_format)|dashboard(s_csp|_studio)))>/
syn match   confWebFeaturesStanzas contained /\v<(feature:(highcharts_accessibility|windows_rce|page_migration|share_job|ui_prefs_optimizations))>/
syn match   confWebFeaturesStanzas contained /\v<(feature::windows_rce|feature:(splunk_web_optimizations|spotlight_search|appserver))>/
syn match   confWebFeaturesStanzas contained /\v<(feature:(search_sidebar|field_filters|identity_sidecar_scim))>/
syn match   confWebFeaturesStanzas contained /\v<(feature:(system_namespace_redirection|federated_search))>/
syn match   confWebFeaturesStanzas contained /\v<(feature:(pdfgen|knowledge_object_favorites|new_data_management_experience|modern-nav))>/
syn match   confWebFeaturesStanzas contained /\v<(feature:(authentication_oauth|search_ai_assistant|splunk_ai_canvas|spl2))>/
syn match   confWebFeaturesStanzas contained /\v<(feature:(splunk_oauth_clients|appserver_security))>/

" Key words
syn match   confWebFeatures /\v<^(enable_(jQuery2|unsupported_hotlinked_imports|dashboard_inputs_localization))>/
syn match   confWebFeatures /\v<^(enable_(dashboards_(external_content|redirection)_restriction|inputs_on_canvas|show_hide|events_viz))>/
syn match   confWebFeatures /\v<^(enable_(acuif_pages|share_job_control))>/
syn match   confWebFeatures /\v<^((internal\.)?dashboards_trusted_domain\.\k+)>/
syn match   confWebFeatures /\v<^(activate_(dsl_webworkers_for_visualizations|save_report_to_dashboard_studio|source_mode_validation))>/
syn match   confWebFeatures /\v<^(allow_multiple_interactions|show_corner_radius_editor|activate_scheduled_export)>/
syn match   confWebFeatures /\v<^(enable_((authoverview|password_management_page)_vnext|react_users_page))>/
syn match   confWebFeatures /\v<^(enable_app_bar_caching|bypass_app_bar_performance_optimizations_apps)>/
syn match   confWebFeatures /\v<^(enable_(spotlight_search|sidebar_preview|field_filters_ui)|enabled)>/
syn match   confWebFeatures /\v<^(activate_downsampling|lazy_load_data_frames_for_visualizations|bypass_clonedeep_options_scope_for_visualizations)>/
syn match   confWebFeatures /\v<^(activate_(dashboard_versioning|add_saved_searches_from_studio|o11y_dashboards))>/
syn match   confWebFeatures /\v<^(enable_(authentication_providers_LDAP|admin_LDAP-groups|authorization_tokens|duo_mfa)_vnext)>/
syn match   confWebFeatures /\v<^(enable_(system_namespace_redirection|ipv6_validations)|execute_chain_searches_with_tokens_in_search_process)>/
syn match   confWebFeatures /\v<^(activate_(o11y_service_graph|(link|save)_to_dashboard_tab))>/
syn match   confWebFeatures /\v<^(enable_(admin_alert_actions|saml)_vnext|check_ai_canvas_eligible)>/
syn match   confWebFeatures /\v<^(enable_((dashboards|reports)_favorites))>/
syn match   confWebFeatures /\v<^(activate_(studio_extension_framework|spl2_datasources))>/
syn match   confWebFeatures /\v<^(activate_scheduled_export_upscaling|enable_new_data_management_home|enable_nav_vnext)>/
syn match   confWebFeatures /\v<^(enable_data_(ui_workflow-actions|props_(sourcetype-rename|fieldaliases)|transforms_extractions)_vnext)>/
syn match   confWebFeatures /\v<^(enable_data_props_(extractions|calcfields)_vnext|enable_data_indexes(_cloud)?_vnext)>/
syn match   confWebFeatures /\v<^(enable_(dashboards|admin_directory|federation_page)_vnext|python\.required)>/
syn match   confWebFeatures /\v<^(enable_(authentication_oauth_ui|search_ai_assistant|spl2))>/
syn match   confWebFeatures /\v<^(enable_splunk_oauth_clients_ui|deactivate_(custom_mako_templates|custom_cherrypy_controllers))>/

" Constants
syn match   confWebFeaturesConstants /\v<(latest|python3\.(7|9))$>/

" Deprecated
syn match   confDeprecated /\v<^(enable_search_v2_endpoint|disable_highcharts_accessibility)>/
syn match   confDeprecated /\v<^(activate_(dashboard_publishing_and_view_without_login|custom_visualizations|conditional_visibility))>/
syn match   confDeprecated /\v<^(activate_chromium_legacy_export|enable_authorization_roles_vnext)>/
syn match   confDeprecated /\v<^(enable_(home|triggered_alerts|datasets|job_manager)_vnext)>/
syn match   confDeprecated /\v<^(enable_(authentication_users|reports|alerts)_vnext)>/
syn match   confDeprecated /\v<^(optimize_ui_prefs_performance)>/
syn match   confDeprecated /\v<^(enable_(autoformatted_comments|app_bar_performance_optimizations|search_bar_performance_optimizations))>/
syn match   confDeprecated /\v<^(enable_(saved_search_pageload_optimization|messages_list_performance_optimizations))>/

" Highlighting
hi def link confWebFeaturesStanzas Identifier
hi def link confWebFeatures Keyword
hi def link confWebFeaturesConstants Constant
hi def link confDeprecated Removed
