" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" visualizations.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confVisualizationsStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
" syn match   confVisualizationsStanzas contained /\v<()>/

syn match   confVisualizations /\v<^(allow_user_selection)>/
syn match   confVisualizations /\v<^(core\.((charting_|mapping_|viz_)?type|height_attribute|icon|order|preview_image|recommend_for))>/
syn match   confVisualizations /\v<^(data_sources(\.([^\.]+\.(mapping_filter(\.center|\.zoom)?|params\.(count|offset|output_mode|search|sort_(direction|key)))))?)>/
syn match   confVisualizations /\v<^(default_(height|width)|description|disabled|label|(max|min)_(height|width)|search_fragment|supports_(drilldown|export|trellis))>/
syn match   confVisualizations /\v<^(trellis_(default_height|min_widths|per_row)|framework_type)>/

" Constants
syn match   confVisualizationsConstants /\v<(json(_rows|_cols)?|asc|desc|(legacy|studio)_visualization)$>/

" Highlighting
hi def link confVisualizationsStanzas Identifier
hi def link confVisualizations Keyword
hi def link confVisualizationsConstants Constant
