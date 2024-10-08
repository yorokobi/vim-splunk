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
syn cluster confStanzas contains=confAuthenticationStanzas,confGenericStanzas

" authentication.conf
syn match  confAuthenticationStanzas contained /\v<(default|authentication|roleMap_[^]]+|cacheTiming|splunk_auth|userToRoleMap_[^]]+)>/
syn match  confAuthenticationStanzas contained /\v<(authenticationResponseAttrMap_SAML|proxysso-authsettings-key|secrets|duo-externalTwoFactorAuthSettings-key)>/
syn match  confAuthentication /\v<^(auth(Type|Settings)|passwordHashAlgorithm|externalTwoFactorAuth(Vendor|Settings)|host|SSLEnabled|port|bindDN(password)?|enablePasswordHistory|passwordHistoryCount|constantLoginTime)>/
syn match  confAuthentication /\v<^((user|group)Base(DN|Filter)|((user|real)Name|email|group(Name|Mapping|Member))Attribute|(network|ldap_negative_cache)_timeout|forceWeakPasswordChange|lockout(Users|(Threshold)?Mins|Attempts))>/
syn match  confAuthentication /\v<^(dynamic(GroupFilter|MemberAttribute)|nestedGroups|charset|anonymous_referrals|(size|time|page)limit|expire((Password|Alert)Days|UserAccounts))>/
syn match  confAuthentication /\v<^(script(Path|SearchFilters)|(userLogin|getUser(s|Info)|attributeQuery)TTL|minPassword(Length|(Upper|Lower)case|Digit|Special)|fqdn|redirectPort)>/
syn match  confAuthentication /\v<^(idp((SSO|SLO|AttributeQuery)Url|CertPath)|errorUrl(Label)?|(entity|issuer)Id|sign(AuthnRequest|edAssertion))>/
syn match  confAuthentication /\v<^(attributeQuery(Soap(Password|Username)|(Request|Response)Signed)|redirectAfterLogoutToUrl|defaultRoleIfMissing)>/
syn match  confAuthentication /\v<^(skipAttributeQueryRequestForUsers|maxAttributeQuery(Threads|QueueSize)|allowSslCompression|cipherSuite)>/
syn match  confAuthentication /\v<^(clientCert|ssl(RootCAPath|VerifyServer(Cert|Name)|Versions|(Alt|Common)NameToCheck|Keysfile(Password)?|Password)|ecdhCurve(s|Name))>/
syn match  confAuthentication /\v<^(ca(CertFile|Path)|blacklisted(AutoMappedRoles|Users)|nameIdFormat|(sso|slo)Binding|(inboundS|s)ignatureAlgorithm)>/
syn match  confAuthentication /\v<^(replicateCertificates|role|realName|mail|disabled|filename|namespace|apiHostname|integrationKey|(appS|s)ecretKey)>/
syn match  confAuthentication /\v<^(failOpen|timeout|useClientSSLCompression|messageOnError|sslVersionsForClient|enableMfaAuthRest|enableRangeRetrieval)>/

" 7.2.3
syn match  confAuthentication /\v<^(verboseLoginFailMsg|authManagerUrl|accessKey|clientId)>/

syn match  confAuthenticationConstants /\v<(Splunk|LDAP|Scripted|SAML|ProxySSO|(MD5|SHA(256|512))-crypt(-\d+)?|RSA-SHA(1|256|384|512))$>/

" 8.1.0
syn match  confAuthenticationStanzas contained /\v<(lockedRoleToFullDNMap_\k+)>/
syn match  confAuthentication /\v<^(python\.version|partialChainCertVerification|script(Functions|Timeout|SecureArguments)|getUsersPrecacheLimit)>/
syn match  confAuthentication /\v<^(assertionTimeSkew|inboundDigestMethod|lockRoleToFullDN|allowPartialSignatures)>/
syn match  confAuthenticationConstants /\v<(default|python(2|3)?)$>/

" 8.2
syn match  confAuthentication /\v<^(getUserInfoTtl|useAuthExtForTokenAuthOnly|excluded(AutoMappedRoles|Users))>/

" 9.0.0
syn match  confAuthentication /\v<^(userInfoTTL)>/
syn match  confAuthenticationConstants /\v<(SHA(1|256|384|512))$>/

" 9.1.0
syn match  confAuthentication /\v<^(idpCertExpiration(WarningDays|CheckInterval))>/

" 9.3.0
syn match  confAuthentication /\v<^(authTypePreferredForUserCollision|saml_negative_cache_timeout|cacheSAMLUserInfotoDisk)>/
syn match  confAuthentication /\v<^(enableAutoMappedRoles|allowEntities)>/
syn match  confAuthenticationConstants /\v<(latest|python3\.(7|9))$>/

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
hi def link confAuthenticationStanzas Identifier
hi def link confAuthenticationConstants Constant
hi def link confAuthentication Keyword
