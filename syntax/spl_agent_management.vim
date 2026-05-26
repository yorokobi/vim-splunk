" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" agent_management.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confAgentManagementStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confAgentManagementStanzas contained /\v<((search|splunkd)_client|settings_sync)>/
syn match   confAgentManagementStanzas contained /\v<(effective_configuration|telemetry|repository_database)>/

" Key words
syn match   confAgentManagement /\v<^(request_timeout|polling_interval)>/
syn match   confAgentManagement /\v<^(query_(agents_(with_error|offline|updated_config)))>/
syn match   confAgentManagement /\v<^(query_agent_version|query_app_summary|connection_(pool_size|keep_alive))>/
syn match   confAgentManagement /\v<^(max_size|cleanup_(schedule|threshold))>/
syn match   confAgentManagement /\v<^(cron_schedule|(collection|job)_timeout)>/
syn match   confAgentManagement /\v<^(stale_csv_cleanup_(ttl|interval)_m|repository_type)>/
syn match   confAgentManagement /\v<^(agents_matching_(max_concurrent_ds_requests|(refresh_(batch_size|interval_s|timeout_m))))>/
syn match   confAgentManagement /\v<^(database_(prune_interval|items_ttl)_h|(app|client|phonehome)_events_(file_limit|ingestion_(interval_m|batch_size)))>/

" Constants
" syn match   confAgentManagementConstants /\v<()$>/

" Deprecated
syn match   confDeprecated /\v<^(fallback_to_deployment_server_ui|log_level)>/

" Highlighting
hi def link confAgentManagementStanzas Identifier
hi def link confAgentManagement Keyword
hi def link confAgentManagementConstants Constant
hi def link confDeprecated Removed
