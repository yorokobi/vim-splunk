" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" serverclass.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confServerClassStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confServerClassStanzas contained /\v<(global|serverClass:\S+(:app:[^]]+)?)>/

" Key words
syn match   confServerClass /\v<^(appFile|(black|white)list\.(\d+|from_pathname|select_field|where_(equals|field)))>/
syn match   confServerClass /\v<^(crossServerChecksum|disabled|endpoint|excludeFromUpdate|filterType|issueReload)>/
syn match   confServerClass /\v<^(machineTypesFilter|precompressBundles|repositoryLocation|restart(IfNeeded|Splunk(d|Web))|stateOnClient)>/
syn match   confServerClass /\v<^(targetRepositoryLocation|tmpFolder|cronSchedule|enable_clustered_mode)>/
syn match   confServerClass /\v<^(syncMode|maxConcurrentDownloads|reloadCheckInterval|applicationMatchingCacheDisabled)>/

" Constants
syn match   confServerClassConstants /\v<((black|white)list|(dis|en)abled|noop)$>/
syn match   confServerClassConstants /\v<(none|sharedDir)$>/

" Deprecated
syn match   confDeprecated /\v<^(continueMatching|(packageTypes|updaterRunning)Filter)>/

" Highlighting
hi def link confServerClassStanzas Identifier
hi def link confServerClass Keyword
hi def link confServerClassConstants Constant
hi def link confDeprecated Removed
