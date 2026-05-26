" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" web.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confWebStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confWebStanzas contained /\v<((endpoint|expose):[^]]+|framework|settings|smc)>/
syn match   confWebStanzas contained /\v<(remoteUI|admin_config_ui|nghttpx_server)>/

" Key words
syn match   confWeb /\v<^(SSOMode|acceptFrom|allowSs(lCompression|lRenegotiation|oWithoutChangingServerConf)|allowableTemplatePaths)>/
syn match   confWeb /\v<^(app(NavReportsLimit|Server(Ports|ProcessShutdownTimeout))|auto_refresh_views|busyKeepAliveIdleTimeout)>/
syn match   confWeb /\v<^(cache(Bytes|Entries)Limit|choropleth_shape_limit|cipherSuite|crossOriginSharingPolicy|customFavicon|dashboard_html_allow_inline_styles)>/
syn match   confWeb /\v<^(dedicatedIoThreads|dhFile|django_((force_)?enable|path)|docsCheckerBaseURL|ecdhCurves|embed_(footer|uri))>/
syn match   confWeb /\v<^(enable(SplunkWebSSL|WebDebug|_(autocomplete|insecure)_login|_gzip|_proxy_write|_risky_command_check(_dashboard)?))>/
syn match   confWeb /\v<^(enabled_decomposers|engine\.autoreload_on|export_timeout|forceHttp10|httpport)>/
syn match   confWeb /\v<^(job_(max|min)_polling_interval|js_logger_mode(_(server_(end_point|(max|poll)_buffer)))?)>/
syn match   confWeb /\v<^(jschart_series_limit|test_mode|truncation_limit(\.(chrome|firefox|ie11|safari))?)>/
syn match   confWeb /\v<^(keepAliveIdleTimeout|listenOnIPv6|log\.access_file|log\.(access|error)_max(files|size)|log\.screen)>/
syn match   confWeb /\v<^(login(BackgroundImageOption|Custom(BackgroundImage|Logo)|(DocumentTitle|Footer)(Option|Text)|PasswordHint|_content))>/
syn match   confWeb /\v<^(max(Sockets|Threads|_(upload|view_cache)_size)|methods|mgmtHostPort|minify_(css|js)|module_dir|oidEnabled|override_JSON_MIME_type_with_text_plain)>/
syn match   confWeb /\v<^(pattern|pdfgen_is_available|pid_path|pivot_adhoc_acceleration_mode|privKeyPath|productMenu(Label|UriPrefix)|remoteGroups(MatchExact|Quoted)?)>/
syn match   confWeb /\v<^(remoteUser(MatchExact)?|replyHeader\.[^\ |\=]+|request\.show_tracebacks|requireClientCert|response\.timeout|(root|rss)_endpoint)>/
syn match   confWeb /\v<^(sendStrictTransportSecurityHeader|server\.(socket_(host|timeout)|thread_(pool(_(max(_spare)?|min_spare))?)))>/
syn match   confWeb /\v<^(serverCert|show(ProductMenu|UserMenuProfile)|simple_(error_page|xml_perf_debug)|skipCSRFProtection|splunkdConnectionTimeout)>/
syn match   confWeb /\v<^(ssl((Alt|Common)NameToCheck|Password|Versions)|ssoAuthFailureRedirect|startwebserver|static(CompressionLevel|_(dir|endpoint)))>/
syn match   confWeb /\v<^(template_dir|termsOfServiceDirectory|testing_(dir|endpoint))>/
syn match   confWeb /\v<^(tools\.(decode\.on|encode\.(encoding|on)|proxy\.(base|on)|sessions\.(forceSecure|httponly|on|restart_persist|secure|storage_(path|type))))>/
syn match   confWeb /\v<^(tools\.sessions\.timeout|tools\.staticdir\.generate_indexes|trap_module_exceptions|trustedIP|ui_inactivity_timeout|updateCheckerBaseURL)>/
syn match   confWeb /\v<^(use_future_expires|userRegistrationURL|verifyCookiesWorkDuringLogin|version_label_format|x_frame_options_sameorigin)>/
syn match   confWeb /\v<^(dashboard_html_allow_iframes|splunk_dashboard_app_name|appServerProcessLogStderr)>/
syn match   confWeb /\v<^(enable_secure_entity_move|enable_insecure_(pdfgen|login)|dashboard_html_(allow_embeddable_content|wrap_embed|allowed_domains))>/
syn match   confWeb /\v<^(engine\.autoreload\.on|tools\.encode\.text_only|crossOriginSharingHeaders|includeSubDomains|preload)>/
syn match   confWeb /\v<^(enable_splunk_dashboard_app_feature|firstTimeLoginMessageOption|firstTimeLoginMessage|allowRemoteProxy)>/
syn match   confWeb /\v<^(pdfgen_trusted_hosts|job_default_auto_cancel|enable_jQuery2)>/
syn match   confWeb /\v<^(sslServerHandshakeTimeout|allow_insecure_libraries_toggle|remoteRoot)>/
syn match   confWeb /\v<^(enableCertBasedUserAuth|certBasedUserAuth(Method|PivOidList)|ssl(RootCAPath|ServerHandShakeTimeout))>/
syn match   confWeb /\v<^(dashboards_csp_allowed_domains|enforce_dashboards_csp|show_app_context)>/
syn match   confWeb /\v<^(enable_risky_command_check_dashboard|allow_insecure_libraries_toggle)>/
syn match   confWeb /\v<^(certBasedUserAuth(Method|PivOidList)|enable_gzip)>/
syn match   confWeb /\v<^(cookieSameSite|optInRemoteUI|allowExternalRemote)>/
syn match   confWeb /\v<^(proxyHostPort|dashboards_trusted_domains_list|allowedSplunkWebClient(Netloc|Scheme)List)>/
syn match   confWeb /\v<^(auto_start|workers|backendConnectionsPerFrontend)>/
syn match   confWeb /\v<^(jschart_test_mode|jschart_truncation_limit(\.(chrome|firefox|safari|ie11))?)>/

" Constants
syn match   confWebConstants /\v<(permissive|strict|auto|never|always|(N|n)one|Firebug|Server|no|yes|only|default|custom|Elastic|AllTime)$>/
syn match   confWebConstants /\v<(lax|not_specified)$>/

" Deprecated
syn match   confDeprecated /\v<^(enableSplunkWebClientNetloc|caCertPath|serviceFormPostURL|supportSSLV3Only|ecdhCurveName)>/
syn match   confDeprecated /\v<^(flash_(major|minor|revision)_version|js_no_cache|enable_pivot_adhoc_acceleration|jschart_results_limit)>/
syn match   confDeprecated /\v<^(enableSearchJobXslt|simplexml_dashboard_create_version|remoteProxyLegacyRequireDoubleEncodedUriArgs)>/

" Highlighting
hi def link confWebStanzas Identifier
hi def link confWeb Keyword
hi def link confWebConstants Constant
