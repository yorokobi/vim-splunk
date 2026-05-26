" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" authentication.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confAuthenticationStanzas,confGenericStanzas

" Stanzas
syn match  confAuthenticationStanzas contained /\v<(authentication|roleMap_[^]]+|cacheTiming|splunk_auth|userToRoleMap_[^]]+)>/
syn match  confAuthenticationStanzas contained /\v<(authenticationResponseAttrMap_SAML|proxysso-authsettings-key|secrets|duo-externalTwoFactorAuthSettings-key)>/
syn match  confAuthenticationStanzas contained /\v<(oauth2_restricted_endpoints|oauth2_settings|oauth2_external_config_[^\]]+)>/
syn match  confAuthenticationStanzas contained /\v<(oauth2_external_(role_mapping|app_client)_[^\]]+)>/
syn match  confAuthenticationStanzas contained /\v<(auth-tokens|splunk_token_settings|lockedRoleToFullDNMap_[^]]+)>/

" Key words
syn match  confAuthentication /\v<^(auth(Type|Settings)|passwordHashAlgorithm|externalTwoFactorAuth(Vendor|Settings)|SSLEnabled|bindDN(password)?|enablePasswordHistory|passwordHistoryCount|constantLoginTime)>/
syn match  confAuthentication /\v<^((user|group)Base(DN|Filter)|((user|real)Name|email|group(Name|Mapping|Member))Attribute|(network|ldap_negative_cache)_timeout|forceWeakPasswordChange|lockout(Users|(Threshold)?Mins|Attempts))>/
syn match  confAuthentication /\v<^(dynamic(GroupFilter|MemberAttribute)|nestedGroups|charset|anonymous_referrals|(size|time|page)limit|expire((Password|Alert)Days|UserAccounts))>/
syn match  confAuthentication /\v<^(script(Path|SearchFilters)|userLogin|getUserInfo|attributeQuery|minPassword(Length|(Upper|Lower)case|Digit|Special)|fqdn|redirectPort)>/
syn match  confAuthentication /\v<^(idp((SSO|SLO|AttributeQuery)Url|CertPath)|errorUrl(Label)?|(entity|issuer)Id|sign(AuthnRequest|edAssertion))>/
syn match  confAuthentication /\v<^(attributeQuery(Soap(Password|Username)|(Request|Response)Signed)|redirectAfterLogoutToUrl|defaultRoleIfMissing)>/
syn match  confAuthentication /\v<^(skipAttributeQueryRequestForUsers|maxAttributeQuery(Threads|QueueSize))>/
syn match  confAuthentication /\v<^(clientCert)>/
syn match  confAuthentication /\v<^(nameIdFormat|(sso|slo)Binding|(inboundS|s)ignatureAlgorithm)>/
syn match  confAuthentication /\v<^(replicateCertificates|role|realName|mail|filename|namespace|apiHostname|integrationKey|(appS|s)ecretKey)>/
syn match  confAuthentication /\v<^(failOpen|timeout|useClientSSLCompression|messageOnError|sslVersionsForClient|enableMfaAuthRest|enableRangeRetrieval)>/
syn match  confAuthentication /\v<^(verboseLoginFailMsg|authManagerUrl|accessKey|clientId)>/
syn match  confAuthentication /\v<^(partialChainCertVerification|script(Functions|Timeout|SecureArguments)|getUsersPrecacheLimit)>/
syn match  confAuthentication /\v<^(assertionTimeSkew|inboundDigestMethod|lockRoleToFullDN|allowPartialSignatures)>/
syn match  confAuthentication /\v<^(getUserInfoTtl|useAuthExtForTokenAuthOnly|excluded(AutoMappedRoles|Users))>/
syn match  confAuthentication /\v<^(user(Login|Info)TTL|attributeQueryTTL)>/
syn match  confAuthentication /\v<^(idpCertExpiration(WarningDays|CheckInterval))>/
syn match  confAuthentication /\v<^(authTypePreferredForUserCollision|saml_negative_cache_timeout|cacheSAMLUserInfotoDisk)>/
syn match  confAuthentication /\v<^(enableAutoMappedRoles|allowEntities)>/
syn match  confAuthentication /\v<^(scimSupportedDomains|scsSyncUserDeletes|signatureRawPubKey)>/
syn match  confAuthentication /\v<^(include(AssertionConsumerServiceURL|Destination)|universalPrompt|hostnames)>/
syn match  confAuthentication /\v<^(certFile|issuer(_uri)?|audience|(clientId|groups)Claim|disable|friendlyName)>/
syn match  confAuthentication /\v<^(jwks_uri|appClient|(created|modified)At|oAuth2Config|roles|ipv(4|6)_cidrs)>/
syn match  confAuthentication /\v<^(maxRequestAge|use_cloudconnect|cloudconnect_tenant)>/

" Constants
syn match  confAuthenticationConstants /\v<(Splunk|LDAP|Scripted|SAML|ProxySSO|(MD5|SHA(256|512))-crypt(-\d+)?|RSA-SHA(1|256|384|512))$>/
syn match  confAuthenticationConstants /\v<(SHA(1|256|384|512))$>/

" Deprecated
syn match  confDeprecated /\v<^(getUser(s|Info)TTL|ecdhCurveName|sslKeysfile(Password)?|caPath|blacklisted(AutoMappedRoles|Users))>/

" Highlighting
hi def link confAuthenticationStanzas Identifier
hi def link confAuthenticationConstants Constant
hi def link confAuthentication Keyword
