" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" deploymentclient.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confDeploymentClientStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confDeploymentClientStanzas contained /\v<(deployment\-client|target-broker:[^]]+)>/

" Key words
syn match   confDeploymentClient /\v<^(clientName|workingDir|repositoryLocation|serverRepositoryLocationPolicy|endpoint)>/
syn match   confDeploymentClient /\v<^(serverEndpointPolicy|phoneHomeIntervalInSecs|handshakeRe(tryIntervalInSecs|plySubscriptionRetry))>/
syn match   confDeploymentClient /\v<^(appEventsResyncIntervalInSecs|reloadDSOnAppInstall)>/
syn match   confDeploymentClient /\v<^(targetUri|(connect|send|recv)_timeout)>/

" Constants
syn match   confDeploymentClientConstants /\v<(accept(SplunkHome|Always)|rejectAlways)$>/

" Highlighting
hi def link confDeploymentClientStanzas Identifier
hi def link confDeploymentClient Keyword
hi def link confDeploymentClientConstants Constant
