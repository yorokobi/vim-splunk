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
syn cluster confStanzas contains=confRestMapStanzas,confGenericStanzas

" restmap.conf
syn match   confRestMapStanzas contained /\v<(global|(admin(_external)?|eai|input|peerupload|script|validation):[^]]+|proxy:appsbrowser|restreplayshc)>/
syn match   confRestMap /\v<^(allow(GetAuth|RestReplay)|(defaultRestReplay|authKey)Stanza|pythonHandlerPath|match|requireAuthentication)>/
syn match   confRestMap /\v<^(restReplay(Stanza)?|capability(\.(post|delete|get|put))?|acceptFrom|includeInAccessLog|xsl|members)>/
syn match   confRestMap /\v<^(script(type|\.arg\.\d+|\.param)?|output_modes|pass(Conf|Http(Cookies|Headers)|Payload|Session|SystemAuth))>/
syn match   confRestMap /\v<^(|driver(\.arg\.\d+|\.env\.[^\ |\=]+)?|showInDirSvc|desc|dynamic|path|untar|methods|destination|filternodes)>/
syn match   confRestMap /\v<^(handler(actions|file|persistentmode|type)?|node(list)?s)>/
syn match   confRestMap /\v<^(python\.version)>/

syn match   confRestMapConstants /\v<(default|python(2|3)?)$>/

" 8.2
syn match   confRestMapConstants /\v<(base64)$>/

" 9.0.0
syn match   confRestMapStanzas contained /\v<(proxybundleupload(rshcluster)?:\k+)>/
syn match   confRestMap /\v<^(stream)>/

" 9.1.0
syn match   confRestMap /\v<^(v1APIBlockGETSearchLaunch|max(CacheTime|RestResults)|streamlineXmlSerialization)>/

" 9.3.0
syn match   confRestMapConstants /\v<(latest|python3\.(7|9))$>/
syn match   confRestMap /\v<^(maxConcurrent)>/

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
hi def link confRestMapStanzas Identifier
hi def link confRestMap Keyword
hi def link confRestMapConstants Constant
