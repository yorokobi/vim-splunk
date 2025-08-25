" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

if version < 600
    syntax clear
elseif exists("b:current_syntax")
    finish
endif

setlocal iskeyword+=.
setlocal iskeyword+=:
setlocal iskeyword+=-

syn case match

syn match confComment /^#.*/ contains=confTodo oneline display
syn match confSpecComment /^\s.*/ contains=confTodo oneline display
syn match confSpecComment /^\*.*/ contains=confTodo oneline display

syn region confString start=/"/ skip="\\\"" end=/"/ oneline display contains=confNumber,confVar
syn region confString start=/`/             end=/`/ oneline display contains=confNumber,confVar
syn region confString start=/'/ skip="\\'"  end=/'/ oneline display contains=confNumber,confVar
syn match  confNumber /\v[+-]?\d+([ywdhsm]|m(on|ins?))(\@([ywdhs]|m(on|ins?))\d*)?>/
syn match  confNumber /\v[+-]?\d+(\.\d+)*>/
syn match  confNumber /\v<\d+[TGMK]B>/
syn match  confNumber /\v<\d+(k)?b>/
syn match  confPath   ,\v(^|\s|\=)\zs(file:|https?:|\$\k+)?(/+\k+)+(:\d+)?,
syn match  confPath   ,\v(^|\s|\=)\zsvolume:\k+(/+\k+)+,
syn match  confVar    /\$\k\+\$/

syn keyword confBoolean on off t[rue] f[alse] T[rue] F[alse]
syn keyword confTodo FIXME[:] NOTE[:] TODO[:] CAUTION[:] contained

" Define generic stanzas
syn match confGenericStanzas display contained /\v[^\]]+/

" Define stanzas
syn region confStanza matchgroup=confStanzaStart start=/^\[/ matchgroup=confStanzaEnd end=/\]/ oneline transparent contains=@confStanzas

" Group clusters
syn cluster confStanzas contains=confWebStanzas,confGenericStanzas

" web.conf
syn match   confWebStanzas contained /\v<(default|(endpoint|expose):[^]]+|framework|settings)>/

syn match   confWeb /\v<^(SSOMode|acceptFrom|allowSs(lCompression|lRenegotiation|oWithoutChangingServerConf)|allowableTemplatePaths)>/
syn match   confWeb /\v<^(app(NavReportsLimit|Server(Ports|ProcessShutdownTimeout))|auto_refresh_views|busyKeepAliveIdleTimeout|caCertPath)>/
syn match   confWeb /\v<^(cache(Bytes|Entries)Limit|choropleth_shape_limit|cipherSuite|crossOriginSharingPolicy|customFavicon|dashboard_html_allow_inline_styles)>/
syn match   confWeb /\v<^(dedicatedIoThreads|dhFile|django_((force_)?enable|path)|docsCheckerBaseURL|ecdhCurve(s|Name)|embed_(footer|uri))>/
syn match   confWeb /\v<^(enable(SplunkWeb(ClientNetloc|SSL)|WebDebug|_(autocomplete|insecure)_login|_gzip|_pivot_adhoc_acceleration|_proxy_write|_risky_command_check(_dashboard)?))>/
syn match   confWeb /\v<^(enabled_decomposers|engine\.autoreload_on|export_timeout|flash_(major|minor|revision)_version|forceHttp10|httpport)>/
syn match   confWeb /\v<^(job_(max|min)_polling_interval|js_logger_mode(_(server_(end_point|(max|poll)_buffer)))?|js_no_cache)>/
syn match   confWeb /\v<^(jschart_((results|series)_limit|test_mode|truncation_limit(\.(chrome|firefox|ie11|safari))?))>/
syn match   confWeb /\v<^(keepAliveIdleTimeout|listenOnIPv6|log\.access_file|log\.(access|error)_max(files|size)|log\.screen)>/
syn match   confWeb /\v<^(login(BackgroundImageOption|Custom(BackgroundImage|Logo)|(DocumentTitle|Footer)(Option|Text)|PasswordHint|_content))>/
syn match   confWeb /\v<^(max(Sockets|Threads|_(upload|view_cache)_size)|methods|mgmtHostPort|minify_(css|js)|module_dir|oidEnabled|override_JSON_MIME_type_with_text_plain)>/
syn match   confWeb /\v<^(pattern|pdfgen_is_available|pid_path|pivot_adhoc_acceleration_mode|privKeyPath|productMenu(Label|UriPrefix)|remoteGroups(MatchExact|Quoted)?)>/
syn match   confWeb /\v<^(remoteUser(MatchExact)?|replyHeader\.[^\ |\=]+|request\.show_tracebacks|requireClientCert|response\.timeout|(root|rss)_endpoint)>/
syn match   confWeb /\v<^(sendStrictTransportSecurityHeader|server\.(socket_(host|timeout)|thread_(pool(_(max(_spare)?|min_spare))?)))>/
syn match   confWeb /\v<^(serverCert|serviceFormPostURL|show(ProductMenu|UserMenuProfile)|simple_(error_page|xml_perf_debug)|skipCSRFProtection|splunkdConnectionTimeout)>/
syn match   confWeb /\v<^(ssl((Alt|Common)NameToCheck|Password|Versions)|ssoAuthFailureRedirect|startwebserver|static(CompressionLevel|_(dir|endpoint))|supportSSLV3Only)>/
syn match   confWeb /\v<^(template_dir|termsOfServiceDirectory|testing_(dir|endpoint))>/
syn match   confWeb /\v<^(tools\.(decode\.on|encode\.(encoding|on)|proxy\.(base|on)|sessions\.(forceSecure|httponly|on|restart_persist|secure|storage_(path|type))))>/
syn match   confWeb /\v<^(tools\.sessions\.timeout|tools\.staticdir\.generate_indexes|trap_module_exceptions|trustedIP|ui_inactivity_timeout|updateCheckerBaseURL)>/
syn match   confWeb /\v<^(use_future_expires|userRegistrationURL|verifyCookiesWorkDuringLogin|version_label_format|x_frame_options_sameorigin)>/

" ----------
"  7.1
" ----------
syn match   confWeb /\v<^(dashboard_html_allow_iframes)>/

syn match   confWebConstants /\v<(permissive|strict|auto|never|always|(N|n)one|Firebug|Server|no|yes|only|default|custom|Elastic|AllTime)$>/

" 7.3.0
syn match   confWeb /\v<^(splunk_dashboard_app_name)>/

" 8.1.0
syn match   confWeb /\v<^(enable_secure_entity_move|enable_insecure_pdfgen|dashboard_html_(allow_embeddable_content|wrap_embed|allowed_domains))>/
syn match   confWeb /\v<^(engine\.autoreload\.on|tools\.encode\.text_only|crossOriginSharingHeaders|includeSubDomains|preload)>/
syn match   confWeb /\v<^(appServerProcessLogStderr|enableSearchJobXslt)>/

" 8.2
syn match   confWeb /\v<^(enable_splunk_dashboard_app_feature|firstTimeLoginMessageOption|firstTimeLoginMessage|simplexml_dashboard_create_version|allowRemoteProxy)>/
syn match   confWeb /\v<^(pdfgen_trusted_hosts|job_default_auto_cancel|enable_jQuery2)>/

" 9.0.0
syn match   confWebStanzas contained /\v<(smc)>/

syn match   confWeb /\v<^(sslServerHandshakeTimeout|allow_insecure_libraries_toggle|remoteRoot)>/
syn match   confWeb /\v<^(enableCertBasedUserAuth|certBasedUserAuth(Method|PivOidList)|ssl(RootCAPath|ServerHandShakeTimeout))>/
syn match   confWeb /\v<^(dashboards_csp_allowed_domains|enforce_dashboards_csp|show_app_context)>/
syn match   confWeb /\v<^(enable_risky_command_check_dashboard|allow_insecure_libraries_toggle)>/

" 9.0.2
syn match   confWeb /\v<^(certBasedUserAuth(Method|PivOidList))>/

" 9.1.1
syn match   confWebConstants /\v<(lax|not_specified)$>/
syn match   confWeb /\v<^(cookieSameSite)>/

" 9.2.0
syn match   confWebStanzas contained /\v<(remoteUI)>/
syn match   confWeb /\v<^(optInRemoteUI|allowExternalRemote)>/

" 9.3.0
syn match   confWeb /\v<^(remoteProxyLegacyRequireDoubleEncodedUriArgs)>/

" 10.0.0
syn match   confWebStanzas contained /\v<(admin_config_ui)>/
syn match   confWeb /\v<^(proxyHostPort|dashboards_trusted_domains_list)>/

" Highlight definitions (generic)
hi def link confComment Comment
hi def link confSpecComment Error
hi def link confBoolean Boolean
hi def link confTodo Todo

" Other highlight
hi def link confString String
hi def link confNumber Number
hi def link confPath   Number
hi def link confVar    PreProc

hi def link confStanzaStart Delimiter
hi def link confstanzaEnd Delimiter

" Highlight for stanzas
hi def link confStanza Function
hi def link confGenericStanzas Constant
hi def link confWebStanzas Identifier
hi def link confWeb Keyword
hi def link confWebConstants Constant
