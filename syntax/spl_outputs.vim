" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" outputs.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confOutputsStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confOutputsStanzas contained /\v<(default|indexAndForward|indexer_discovery:[^]]+|syslog(:[^]]+)?|tcpout(-server:\/\/\S+:\d+|:[^]]+)?|remote_queue:\S+)>/
syn match   confOutputsStanzas contained /\v<(httpout|rfs(:\k+)?|cloud_processing_queue)>/

" Key words
syn match   confOutputs /\v<^(ackTimeoutOnShutdown|autoLB(Frequency|Volume)|backoffOnFailure|block(OnCloning|WarnThreshold)|channel(Reap(Interval|Lowater)|TTL))>/
syn match   confOutputs /\v<^(cipherSuite|clientCert|compressed|(connection|read|write)Timeout|(cxn|rcv|send)_timeout|defaultGroup|(dnsResolution|secsInFailure)Interval|drop(Cloned)?EventsOnQueueFull)>/
syn match   confOutputs /\v<^(ecdhCurves|forceTimebasedAutoLB|forwardedindex\.(\d+\.(black|white)list|filter\.disable)|heartbeatFrequency|index(AndForward|erDiscovery)?)>/
syn match   confOutputs /\v<^(manager_uri|max(ConnectionsPerIndexer|(Event|Queue)Size|FailuresPerInterval)|negotiateProtocolLevel|pass4SymmKey)>/
syn match   confOutputs /\v<^(priority|selectiveIndexing|sendCookedData|server|socks(Password|ResolveDNS|Server|Username)|syslogSourceType|tcpSendBufSz)>/
syn match   confOutputs /\v<^(ssl((Alt|Common)NameToCheck|Password|VerifyServerCert|Versions))>/
syn match   confOutputs /\v<^(timestampformat|tlsHostname|token|type|use(ACK|ClientSSLCompression))>/
syn match   confOutputs /\v<^(remote_queue\.|remote_queue\.sqs\.((access|secret)_key|auth_region|endpoint|message_group_id|retry_policy|max_count\.max_retries_per_part|timeout\.(connect|read|write)))>/
syn match   confOutputs /\v<^(remote_queue\.sqs\.(large_message_store\.(endpoint|path)|send_interval|max_queue_message_size|enable_(data_integrity_checks|signed_payloads)))>/
syn match   confOutputs /\v<^(concurrentChannelLimit)>/
syn match   confOutputs /\v<^(useSSL|remote_queue\.type|remote_queue\.kinesis\.((access|secret)_key|auth_region|endpoint))>/
syn match   confOutputs /\v<^(remote_queue\.kinesis\.(enable_(data_integrity_checks|signed_payloads)|retry_policy))>/
syn match   confOutputs /\v<^(remote_queue\.kinesis\.(max_count.max_retries_per_part|timeout\.(connect|read|write)))>/
syn match   confOutputs /\v<^(remote_queue\.kinesis\.large_message_store\.(endpoint|path))>/
syn match   confOutputs /\v<^(remote_queue\.kinesis\.(send_interval|max_queue_message_size))>/
syn match   confOutputs /\v<^(connectionTTL|remote_queue\.kinesis\.tenantId)>/
syn match   confOutputs /\v<^(httpEventCollectorToken|uri|batch(Size|Timeout))>/
syn match   confOutputs /\v<^(remote_queue\.sqs_smartbus\.((access|secret)_key|auth_region|endpoint|message_group_id|retry_policy))>/
syn match   confOutputs /\v<^(remote_queue\.sqs_smartbus\.(max_count\.max_retries_per_part|timeout\.(connect|read|write)))>/
syn match   confOutputs /\v<^(remote_queue\.sqs_smartbus\.(large_message_store\.(endpoint|path)|send_interval|max_queue_message_size))>/
syn match   confOutputs /\v<^(remote_queue\.sqs_smartbus\.(enable_(data_integrity_checks|signed_payloads)|executor_max_(workers|jobs)_count))>/
syn match   confOutputs /\v<^(polling_interval|maxSendQSize|remote_queue.sqs_smartbus.encoding_format)>/
syn match   confOutputs /\v<^(remote_queue.sqs_smartbus.large_message_store.(encryption_scheme|kms_endpoint|key_(id|refresh_interval)))>/
syn match   confOutputs /\v<^(connectionsPerTarget|autoLBFrequencyIntervalOnGroupFailure|autoBatch|sslVerifyServerName)>/
syn match   confOutputs /\v<^(remote_queue.sqs_smartbus.large_message_store.(ssl(VerifyServerCert|Versions|(Alt|Common)NameToCheck|RootCAPath)))>/
syn match   confOutputs /\v<^(remote_queue.sqs_smartbus.large_message_store.(cipherSuite|ecdhCurves|dhFile))>/
syn match   confOutputs /\v<^(dropEventsOnUploadError|batchSizeThresholdKB|compression(Level)?|path|description)>/
syn match   confOutputs /\v<^(remote.s3.(encryption|(access|secret)_key|(signature|url)_version|supports_versioning|endpoint|retry_policy))>/
syn match   confOutputs /\v<^(remote.s3.(ssl(VerifyServerCert|Versions|(Alt|Common)NameToCheck|RootCAPath)|cipherSuite|ecdhCurves))>/
syn match   confOutputs /\v<^(remote.s3.(kms.(auth_region|key_id)|authMethod))>/
syn match   confOutputs /\v<^(partitionBy|metadata_max_attempts)>/
syn match   confOutputs /\v<^(remote\.s3\.kms\.(ssl(VerifyServerCert|Versions|RootCAPath|AltNamesToCheck|CommonNameToCheck)|cipherSuite|ecdhCurves|dhFile))>/
syn match   confOutputs /\v<^(enableOldS2SProtocol|partitionBy|format(\.(nd)?json\.index_time_fields)?|disabled|)>/
syn match   confOutputs /\v<^(remote_queue\.sqs_smartbus\.(consume_interval|drop_data(_index_list)?|enable_inline_data))>/
syn match   confOutputs /\v<^(remote\.s3\.auth_region)>/
syn match   confOutputs /\v<^(certRotation(CheckInterval|ThresholdPct)|autoCertRotation)>/
syn match   confOutputs /\v<^(remote_queue\.sqs_smartbus\.check_replication_(enabled|interval|executor_max_workers_count|executor_max_jobs_count))>/
syn match   confOutputs /\v<^(remote_queue\.sqs_smartbus\.enable_shared_receipts|fs\.appendToFileUntilSizeMB|fs\.timeBeforeClosingFileSecs)>/
syn match   confOutputs /\v<^(remote\.s3\.metadata_max_attempts|remote\.sts\.assume_role\.(role_arn|external_id|duration_secs)|authMethod)>/
syn match   confOutputs /\v<^(queueSize|persistentQueueSize)>/
syn match   confOutputs /\v<^(remote_queue\.asq\.(encoding_format|enable_inline_data|(access|secret)_key|endpoint|retry_policy))>/
syn match   confOutputs /\v<^(remote_queue\.asq\.(max_count\.max_retries_in_total|timeout\.(connect|read|write)))>/
syn match   confOutputs /\v<^(remote_queue\.asq\.large_message_store\.(endpoint|path|container_name|ssl(VerifyServerCert|Versions|RootCAPath)|cipherSuite))>/
syn match   confOutputs /\v<^(remote_queue\.asq\.(send_interval|max_queue_message_size|drop_data(_index_list)?))>/
syn match   confOutputs /\v<^(remote_queue\.asq\.(executor_max_(workers|jobs)_count|large_message_store\.encryption_scheme))>/
syn match   confOutputs /\v<^(remote_queue\.asq\.(azure-sse-kv\.encryptionScope|large_message_store\.azure-sse-c\.key_type))>/
syn match   confOutputs /\v<^(remote_queue\.asq\.large_message_store\.azure-sse-c\.azure_kv\.(key_(name|vault_(tenant|client)_id)|endpoint|key_vault_client_secret))>/
syn match   confOutputs /\v<^(remote_queue\.asq\.large_message_store\.enable_shared_receipts)>/
syn match   confOutputs /\v<^(remote_queue\.gcs_smartbus\.back_off_policy_option\.(initial|max|scaling))>/
syn match   confOutputs /\v<^(remote_queue\.gcs_smartbus\.(credential_file|enable_inline_data|encoding_format))>/
syn match   confOutputs /\v<^(remote_queue\.gcs_smartbus\.large_message_store\.(cipherSuite|connectUsingIpVersion))>/
syn match   confOutputs /\v<^(remote_queue\.gcs_smartbus\.large_message_store\.encryption(\.gcp-sse-c\.key_(type|refresh_interval))?)>/
syn match   confOutputs /\v<^(remote_queue\.gcs_smartbus\.large_message_store\.gcp_kms\.(key(_ring)?|locations))>/
syn match   confOutputs /\v<^(remote_queue\.gcs_smartbus\.large_message_store\.ssl(RootCAPath|VersionsForClient|VerifyServer(Name|Cert)))>/
syn match   confOutputs /\v<^(remote_queue\.gcs_smartbus\.max_(hold_time|pending_messages)_option)>/
syn match   confOutputs /\v<^(remote_queue\.gcs_smartbus\.(retry_policy_option|send_interval|storage_endpoint))>/
syn match   confOutputs /\v<^(remote_queue\.gcs_smartbus\.(project_id|large_message_store\.path|pubsub_endpoint))>/

" Constants
syn match   confOutputsConstants /\v<(auto|NO_PRI|tcp|udp|max_count|none)$>/
syn match   confOutputsConstants /\v<(legacy|sqs|kinesis)$>/
syn match   confOutputsConstants /\v<(sqs(_smartbus(_cp)?)|kinesis)$>/
syn match   confOutputsConstants /\v<(protobuf|s2s|sse-(s3|c))$>/
syn match   confOutputsConstants /\v<(sse-(s3|kms)|cse|zstd|lz4|gzip)$>/
syn match   confOutputsConstants /\v<(legacy|year|month|day|sourcetype)$>/
syn match   confOutputsConstants /\v<((nd)?json|raw)$>/
syn match   confOutputsConstants /\v<(asq|azure-sse-(kv|ms|c))$>/
syn match   confOutputsConstants /\v<(gcs_smartbus|(4|6)-only|gcp-sse-(c|kms|gcp))$>/

" Deprecated
syn match   confOutputsDeprecated /\v<^(negotiateNewProtocol|ssl(CertPath|Cipher|RootCAPath|QuietShutdown)|master_uri)>/

" Highlighting
hi def link confOutputsStanzas Identifier
hi def link confOutputs Keyword
hi def link confOutputsConstants Constant
hi def link confOutputsDeprecated Removed
