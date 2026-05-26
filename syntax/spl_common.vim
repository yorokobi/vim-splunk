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

syn match confComment /^#.*/ contains=confTodo,confDeprecated oneline display
syn match confSpecComment /^\s.*/ contains=confTodo,confDeprecated oneline display
syn match confSpecComment /^\*.*/ contains=confTodo,confDeprecated oneline display

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
syn keyword confDeprecated DEPRECATED[.:;] UNSUPPORTED[.;:] REMOVED[.;:] contained

" Define generic stanzas
syn match confGenericStanzas display contained /\v[^\]]+/

" Define stanzas
syn region confStanza matchgroup=confStanzaStart start=/^\[/ matchgroup=confStanzaEnd end=/\]/ oneline transparent contains=@confStanzas

" Group clusters
syn cluster confStanzas contains=confCommonStanzas,confCommonDeprecatedStanzas ,confGenericStanzas

" Common Stanzas
syn match  confCommonStanzas contained /\v<(default|general)>/

" Common Key Words
syn match  confCommon /\v<^(acceptFrom|allowSslCompression|caCertFile|cipherSuite|description|disabled|ecdhCurve(s|Name))>/
syn match  confCommon /\v<^(enabled|filename|index|interval|label|name|password|path|port|priority|python\.required)>/
syn match  confCommon /\v<^(remote\.s3\.(encryption|endpoint|supports_versioning)|search|type|host)>/
syn match  confCommon /\v<^(ssl((Alt|Common)NameToCheck|Password|RootCAPath|VerifyServer(Cert|Name)|Versions))>/

" Common Constants
syn match  confCommonConstants /\v<(enabled|disabled|latest|default|tls1\.(0|1|2|3)|python(2|3)?|python3\.(7|9))$>/
syn match  confCommonConstants /\v<(both|all)$>/

" Deprecated
syn match  confCommonDeprecated /\v<^(python\.version)>/
" Customize the Removed syntax for deprecated and unsupported
" stanzas, key words, constants, etc.
hi Removed cterm=Bold ctermfg=Black ctermbg=Yellow guifg=Black guibg=Yellow 

" Highlight definitions (generic)
hi def link confComment Comment
hi def link confSpecComment Comment
hi def link confBoolean Boolean
hi def link confTodo Todo
hi def link confDeprecated Removed

" Other highlight
hi def link confString String
hi def link confNumber Number
hi def link confPath   Number
hi def link confVar    PreProc

hi def link confStanzaStart Delimiter
hi def link confstanzaEnd Delimiter

" Highlight for stanzas
hi def link confStanza Identifier
hi def link confGenericStanzas Constant
hi def link confCommon Keyword
hi def link confCommonStanzas Identifier
hi def link confCommonConstants Constant
hi def link confCommonDeprecatedStanzas Removed
hi def link confCommonDeprecated Removed
