" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" metric_rollups.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confMetricRollupsStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
syn match   confMetricRollupsStanzas contained /\v<(index:[^]]+)>/

" Key words
syn match   confMetricRollups /\v<^(defaultAggregation|dimensionList(Type)?|aggregation\.\S+|rollup\.\S+\.(span|rollupIndex))>/
syn match   confMetricRollups /\v<^(metricList(Type)?)>/

" Constants
syn match   confMetricRollupsConstants /\v<(avg|count|max|median|min|perc\d+|sum|(ex|in)cluded)$>/

" Highlighting
hi def link confMetricRollupsStanzas Identifier
hi def link confMetricRollups Keyword
hi def link confMetricRollupsConstants Constant
