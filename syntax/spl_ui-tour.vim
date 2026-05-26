" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" ui-tour.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confUITourStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
" syn match   confUITourStanzas contained /\v<()>/

" Key words
syn match   confUITour /\v<^((use|next|force)Tour|intro|type|label|(tour|manager)Page|viewed)>/
syn match   confUITour /\v<^((skip|done)Text|doneURL|image(Name|Caption)\d+|imgPath|context)>/
syn match   confUITour /\v<^(urlData|step(Text|Element|Position|Click(Event|Element))\d+)>/

" Constants
syn match   confUITourConstants /\v<(image|interactive|system|bottom|right|left|top|click|mouse(down|up))$>/

" highlighting
hi def link confUITourStanzas Identifier
hi def link confUITour Keyword
hi def link confUITourConstants Constant
