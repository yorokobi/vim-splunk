" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" federated.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confFederatedStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confFederatedStanzas contained /\v<(provider)>/
syn match   confFederatedStanzas contained /\v<(s2s_standard_mode_unsupported_command:meta(data|search))>/
syn match   confFederatedStanzas contained /\v<(s2s_transparent_mode_unsupported_command:(makeresults|delete|dump|map|run(shellscript)?))>/
syn match   confFederatedStanzas contained /\v<(s2s_transparent_mode_unsupported_command:(script|send(alert|email)|rest|summarize|tstats))>/
syn match   confFederatedStanzas contained /\v<(s2s_unsupported_command:show_source|features|s2s_transparent_mode_unsupported_command:loadjob)>/

" Key words
syn match   confFederated /\v<^(type|ip|splunk\.(port|serviceAccount|app)|mode)>/
syn match   confFederated /\v<^(hostPort|serviceAccount|password|appContext|useFSHKnowledgeObjects)>/
syn match   confFederated /\v<^(needs_consent|heartbeat(Enabled|Interval)|connectivityFailuresThreshold)>/
syn match   confFederated /\v<^(controlCommands(Max(Threads|TimeThreshold)|FeatureEnabled))>/
syn match   confFederated /\v<^(proxyBundlesTTL|remoteEventsDownloadRetryCountMax|remoteEventsDownloadRetryTimeoutMs|verbose_mode)>/
syn match   confFederated /\v<^(max_preview_generation_duration|active|allow_target|rsh_min_version_(cloud|onprem))>/
syn match   confFederated /\v<^(max_preview_generation_inputcount|previewOnRshEnabled)>/
syn match   confFederated /\v<^(allow(LookupsToExistOnlyOnRshForStandardMode|edAndDefaultFederatedProvidersEnabled))>/
syn match   confFederated /\v<^(s2s_standard_mode_local_only_commands|useAppContextFromSearch|fedSrchIndexesAllowed)>/
syn match   confFederated /\v<^(providerVerificationMode|enable_streaming_optimization|federated_search_retry_count)>/
syn match   confFederated /\v<^(federated_search_(remote_ttl|max_events_per_bucket))>/
syn match   confFederated /\v<^(sal_api_base_url|rsh_delta_write_timeout|skipLoadWithoutPpcFor|expand_federated_index_wildcard_only)>/
syn match   confFederated /\v<^(allow(CaseInsensitivityForFederatedProvider|IndexBasedProviderFiltering|Ast(ProjectionElim|PredicateMerge)))>/
syn match   confFederated /\v<^(allowAst(InsertRedistributeCommand|Replace(ChartCmds|DatamodelStatsCmds)WithTstats))>/
syn match   confFederated /\v<^(allowAstReplace(TableWithFields|SdselectWithSdsql)|proxyBundleToCaptainEnabled)>/
syn match   confFederated /\v<^(fsh(FeaturesTransactionRequestEnabled|HeartbeatRest(Connect|Read)Timeout))>/
syn match   confFederated /\v<^(proxyBundleFromMemberToCaptain(Connection|Read|Write)Timeout)>/
syn match   confFederated /\v<^(legacy_aws_federated_(provider|index)_support)>/

" Constants
syn match   confFederatedConstants /\v<(deactivated|audit|strict|auto)$>/
syn match   confFederatedConstants /\v<(splunk|aws_s3|standard|transparent)$>/

" Highlighting
hi def link confFederatedStanzas Identifier
hi def link confFederated Keyword
hi def link confFederatedConstants Constant
