" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" restmap.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confRestMapStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confRestMapStanzas contained /\v<((admin(_external)?|eai|input|peerupload|script|validation):[^]]+)>/
syn match   confRestMapStanzas contained /\v<(proxybundleupload(rshcluster)?:\k+|proxybundleshc(member|captain):\k+)>/
syn keyword confRestMapStanzas contained global proxy:appsbrowser restreplayshc

" Key words
syn match   confRestMap /\v<^(allow(GetAuth|RestReplay)|(defaultRestReplay|authKey)Stanza)>/
syn match   confRestMap /\v<^(restReplay(Stanza)?|capability(\.(post|delete|get|put))?)>/
syn match   confRestMap /\v<^(script(type|\.arg\.\d+|\.param)?|pass(Conf|Http(Cookies|Headers)|Payload|Session|SystemAuth))>/
syn match   confRestMap /\v<^(|driver(\.arg\.\d+|\.env\.[^\ |\=]+)?|max(CacheTime|RestResults))>/
syn match   confRestMap /\v<^(handler(actions|file|persistentmode|type)?|node(list)?s)>/
syn match   confRestMap /\v<^(pythonHandlerPath|match|requireAuthentication|acceptFrom|includeInAccessLog|xsl|members|output_modes)>/
syn match   confRestMap /\v<^(showInDirSvc|desc|dynamic|path|untar|methods|destination|filternodes|stream|max_content_length)>/
syn match   confRestMap /\v<^(maxConcurrent|v1APIBlockGETSearchLaunch|streamlineXmlSerialization)>/

" Constants
syn match   confRestMapConstants /\v<(base64|unlimited)$>/

" Highlighting
hi def link confRestMapStanzas Identifier
hi def link confRestMap Keyword
hi def link confRestMapConstants Constant
