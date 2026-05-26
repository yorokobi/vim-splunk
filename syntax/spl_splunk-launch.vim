" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" splunk-launch.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confSplunkLaunchStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
" syn match   confSplunkLaunchStanzas contained /\v<(default)>/

" Key words
syn match   confSplunkLaunch /\v<^(SPLUNK_(FIPS|BINDIP|DB|HOME|IGNORE_SELINUX|OS_USER|(SERVER|WEB)_NAME)|OPTIMISTIC_ABOUT_FILE_LOCKING)>/
syn match   confSplunkLaunch /\v<^(SPLUNK_PYTHON_DONT_ESCAPE_PRINTABLE|ENABLE_CPUSHARES|SPLUNK_FIPS_VERSION|PYTHONHTTPSVERIFY|PYTHONUTF8)>/

" Constants
syn match   confSplunkLaunchConstants /\v<(140-(2|3))$>/

" Highlighting
hi def link confSplunkLaunchStanzas Identifier
hi def link confSplunkLaunch Keyword
hi def link confSplunkLaunchConstants Constant
