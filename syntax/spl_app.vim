" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" app.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confAppStanzas,confGenericStanzas

" Stanzas
syn match   confAppStanzas contained /\v<(author|id|launcher|package|install|triggers|ui|credentials_settings|credential:[^]]+|diag|shclustering)>/
syn match   confAppStanzas contained /\v<(data_management)>/

" Key words
syn match   confApp /\v<^(email|company|group|name|version|remote_tab|version|description|author|id|check_for_updates)>/
syn match   confApp /\v<^(state(_change_requires_restart)?|build|allows_disable|install_source(_local)?_checksum|attribution_link)>/
syn match   confApp /\v<^(reload\.[^\ |\=]+|is_(visible|configured|manageable)|show_in_nav|label|docs_section_override)>/
syn match   confApp /\v<^(setup_view|verify_script|password|extension_script|data_limit|default_gather_lookups)>/
syn match   confApp /\v<^(deployer_(lookups_)?push_mode|show_upgrade_notification|plugin_enabled|supported_themes)>/

" Constants
syn match   confAppConstants /\v<(never|simple|(rest|access)_endpoints|http_(get|post))$>/
syn match   confAppConstants /\v<(preserve_lookups|always_(preserve|overwrite)|full|merge_to_default|(local|default)_only)$>/
syn match   confAppConstants /\v<(overwrite_on_change|dark|light)$>/

" Highlighting 
hi def link confAppStanzas Identifier
hi def link confApp Keyword
hi def link confAppConstants Constant
