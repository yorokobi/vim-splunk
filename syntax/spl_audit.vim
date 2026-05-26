" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" audit.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confAuditStanzas,confGenericStanzas

" Stanzas
syn match   confAuditStanzas contained /\v<(auditTrail|auditconfig:\/\k+((\/\k+)+)?)>/

" Key words
syn match   confAudit /\v<^(queueing|logging_format|sampling\.\k+)>/

" Constants
syn match   confAuditConstants /\v<(v(1|2))$>/

hi def link confAuditStanzas Identifier
hi def link confAuditConstants Constant
hi def link confAudit Keyword
