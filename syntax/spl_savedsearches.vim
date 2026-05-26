" Vim syntax file
" Language: Splunk configuration files
" Maintainer: Colby Williams <colbyw at gmail dot com>

" savedsearches.conf

" Source common highlight elements
source <sfile>:p:h/spl_common.vim

" Group clusters
syn cluster confStanzas contains=confSavedSearchesStanzas,confCommonStanzas,confGenericStanzas

" Stanzas
" syn match   confSavedSearchesStanzas contained /\v<()>/

" Key words
syn match   confSavedSearches /\v<^(action\.email(\.(from|include\.(results_link|search|trigger(_time)?|view_link)|inline|mailserver|maxresults|send(csv|pdf|results|png)|subject|to|(b)cc))?)>/
syn match   confSavedSearches /\v<^(action\.lookup(\.(append|filename))?|action\.populate_lookup(\.dest)?|action\.script(\.filename)?)>/
syn match   confSavedSearches /\v<^(action\.summary_index(\.(_name|inline|[^\ |\=]+))?|action\.rss|allow_skew)>/
syn match   confSavedSearches /\v<^(alert\.(digest_mode|display_view|expires|managedBy|severity|suppress(\.fields|\.period)?|track)|alert_condition)>/
syn match   confSavedSearches /\v<^(auto_summarize(\.(command|cron_schedule|dispatch\.[^\ |\=]+|hash|max_(concurrent|disabled_buckets|summary_(ratio|size)|time)))?)>/
syn match   confSavedSearches /\v<^(auto_summarize\.(normalized_hash|suspend_period|timespan)|counttype|cron_schedule|description|disabled)>/
syn match   confSavedSearches /\v<^(dispatch\.(auto_(cancel|pause)|buckets|(earliest|latest)_time|index(_(earliest|latest)|edRealtime(MinSpan|Offset)?)))>/
syn match   confSavedSearches /\v<^(dispatch(\.(lookups|max_(count|time)|reduce_freq|rt_(backfill|maximum_span)|sample_ratio|spawn_process|time_format|ttl)|As))>/
syn match   confSavedSearches /\v<^(display\.events\.(fields|(list|table)\.(drilldown|wrap)|maxLines|raw\.drilldown|rowNumbers|type))>/
syn match   confSavedSearches /\v<^(display\.general\.(enablePreview|locale|migratedFromViewState|timeRangePicker\.show|type))>/
syn match   confSavedSearches /\v<^(display\.page\.(pivot\.dataModel|search\.(mode|patterns\.sensitivity|showFields|tab|timeline\.(format|scale))))>/
syn match   confSavedSearches /\v<^(display\.statistics\.drilldown|action_(email|rss))>/
syn match   confSavedSearches /\v<^(display\.statistics\.format\.([^\ |\=|\.]+)(\.colorPalette(\.(colors|interpolate|(max|mid|min)Color|rule))?)?)>/
syn match   confSavedSearches /\v<^(display\.statistics\.format\.([^\.]+)\.(field(s)?|precision|scale(\.(base|categories|(max|mid|min)(Type|Value)|thresholds))?))>/
syn match   confSavedSearches /\v<^(display\.statistics\.format\.([^\.]+)\.(unit(Position)?|useThousandSeparators))>/
syn match   confSavedSearches /\v<^(display\.statistics\.(overlay|percentagesRow|rowNumbers|show|totalsRow|wrap))>/
syn match   confSavedSearches /\v<^(display\.visualizations\.chart(Height|ing\.axis(LabelsX\.majorLabelStyle\.(overflowMode|rotation))|ing\.lineWidth))>/
syn match   confSavedSearches /\v<^(display\.visualizations\.charting\.axis(Labels(X|Y(2)?)\.majorUnit))>/
syn match   confSavedSearches /\v<^(display\.visualizations\.charting\.axisTitleX\.(text|visibility))>/
syn match   confSavedSearches /\v<^(display\.visualizations\.charting\.axisTitleY((2)?\.visibility|(2)?\.text))>/
syn match   confSavedSearches /\v<^(display\.visualizations\.charting\.axisX\.((max|min)imumNumber|scale|abbreviation))>/
syn match   confSavedSearches /\v<^(display\.visualizations\.charting\.axisY(2)?\.(enabled|(max|min)imumNumber|scale|abbreviation))>/
syn match   confSavedSearches /\v<^(display\.visualizations\.charting\.chart\.bubble((Max|Min)imumSize|SizeBy))>/
syn match   confSavedSearches /\v<^(display\.visualizations\.charting\.chart(\.nullValueMode|\.overlayFields|\.rangeValues)?)>/
syn match   confSavedSearches /\v<^(display\.visualizations\.charting\.chart\.(showDataLabels|sliceCollapsingThreshold|stackMode|style))>/
syn match   confSavedSearches /\v<^(display\.visualizations\.charting\.(drilldown|fieldDashStyles|gaugeColors|layout\.(splitSeries(\.allowIndependentYRanges)?)))>/
syn match   confSavedSearches /\v<^(display\.visualizations\.charting\.legend\.(mode|labelStyle\.overflowMode|placement))>/
syn match   confSavedSearches /\v<^(display\.visualizations\.custom\.(height|type|drilldown))>/
syn match   confSavedSearches /\v<^(display\.visualizations\.(mapHeight|show|singlevalueHeight|type))>/
syn match   confSavedSearches /\v<^(display\.visualizations\.mapping\.choroplethLayer\.color(Bins|Mode))>/
syn match   confSavedSearches /\v<^(display\.visualizations\.mapping\.choroplethLayer\.((max|min)imumColor|neutralPoint|shapeOpacity|showBorder))>/
syn match   confSavedSearches /\v<^(display\.visualizations\.mapping\.(data\.maxClusters|drilldown|showTiles|type|legend\.placement))>/
syn match   confSavedSearches /\v<^(display\.visualizations\.mapping\.map\.(center|panning|scrollZoom|zoom))>/
syn match   confSavedSearches /\v<^(display\.visualizations\.mapping\.markerLayer\.marker((Max|Min)Size|Opacity))>/
syn match   confSavedSearches /\v<^(display\.visualizations\.mapping\.tileLayer\.((max|min)Zoom|tileOpacity|url))>/
syn match   confSavedSearches /\v<^(display\.visualizations\.singlevalue\.((after|before)Label|color(By|Mode)))>/
syn match   confSavedSearches /\v<^(display\.visualizations\.singlevalue\.(numberPrecision|range(Colors|Values)|show(Sparkline|TrendIndicator)))>/
syn match   confSavedSearches /\v<^(display\.visualizations\.singlevalue\.(trend(ColorInterpretation|DisplayMode|Interval)|underLabel|unit(Position)?|drilldown))>/
syn match   confSavedSearches /\v<^(display\.visualizations\.singlevalue\.use(Colors|ThousandSeparators))>/
syn match   confSavedSearches /\v<^(display\.visualizations\.trellis\.(enabled|scales\.shared|size|splitBy))>/
syn match   confSavedSearches /\v<^(displayview|embed\.enabled|enableSched|is_visible|max_concurrent|nextrun|qualifiedSearch|request\.ui_dispatch_(app|view))>/
syn match   confSavedSearches /\v<^(run_(n_times|on_startup)|schedule(_window|_priority))>/
syn match   confSavedSearches /\v<^(search|sendresults|(user|vs)id)>/
syn match   confSavedSearches /\v<^(auto_summarize\.workload_pool|display\.visualizations\.charting\.fieldColors|federated\.provider)>/
syn match   confSavedSearches /\v<^(action\.email\.allow_empty_attachment|alert\.suppress\.group_name)>/
syn match   confSavedSearches /\v<^(schedule_as|dispatch.allow_partial_results|skip_scheduled_realtime_idxc)>/
syn match   confSavedSearches /\v<^(durable.((track_time|backfill)_type|lag_time|max_backfill_intervals)|action.summary_metric_index.(inline|_name)?)>/
syn match   confSavedSearches /\v<^(defer_scheduled_searchable_idxc|quantity|query|realtime_schedule|relation|restart_on_searchpeer_add|role)>/
syn match   confSavedSearches /\v<^(workload_pool)>/
syn match   confSavedSearches /\v<^(dispatch.rate_limit_retry|precalculate_required_fields_for_alerts)>/
syn match   confSavedSearches /\v<^(calculate_alert_required_fields_in_search)>/
syn match   confSavedSearches /\v<^(allow_data_time_skew|federated_providers)>/

" Constants
syn match   confSavedSearchesConstants /\v<(user|owner|inner|outer|full|none|raw|list|table|events|statistics|visualizations|fast|smart|verbose|patterns)$>/
syn match   confSavedSearchesConstants /\v<(hidden|compact|full|line(ar)?|log|row|cell|color|number|expression|map|minMidMax|shared(Category|List)|auto)$>/
syn match   confSavedSearchesConstants /\v<(categor(y|ical)|threshold|number|percent(ile)?|before|after|heatmap|highlow|ellipsis(Middle|None|End|Middle|Start)|visible|collapsed|all)$>/
syn match   confSavedSearchesConstants /\v<(inherit|(filler|marker|radial)Gauge|area|column|bar|pie|scatter|bubble|diameter|gaps|zero|connect|minmax|default)$>/
syn match   confSavedSearchesConstants /\v<(stacked(100)?|minimal|shiny|standard|seriesCompare|right|bottom(right)?|top|left|sequential|divergent)$>/
syn match   confSavedSearchesConstants /\v<(marker|choropleth|value|trend|block|inverse|absolute|large|medium|small|custom|mapping|singlevalue|charting)$>/
syn match   confSavedSearchesConstants /\v<((greater|less)\ than|(not\ )?equal\ to|(drops|rises)\ by|high(er|est))$>/
syn match   confSavedSearchesConstants /\v<(number\ of\ (events|hosts|sources)|always)$>/
syn match   confSavedSearchesConstants /\v<(classic|prjob|_(index)?time|time_(interval|whole))$>/

" Deprecated
syn match   confSavedSearchesDeprecated /\v<^(schedule)>/

" alert_logevent
" etc/apps/alert_logevent/README/savedsearches.conf.spec
syn match   confSavedSearches /\v<action\.(logevent(\.param\.(event|host|source(type)?|index))|log_event)>/

" alert_webhook
" etc/apps/alert_webhook/README/savedsearches.conf.spec
syn match   confSavedSearches /\v<action\.webhook(\.param\.url)?>/

" splunk_monitoring_console
" etc/apps/splunk_monitoring_console/README/savedsearches.conf.spec
syn match   confSavedSearches /\v<display\.visualizations\.custom\.splunk_monitoring_console\.heatmap\.(baseColor|legendTitle|showLegend|showTooltip|(show)?([XxYy])Axis)>/

" Highlighting
hi def link confSavedSearchesStanzas Identifier
hi def link confSavedSearches Keyword
hi def link confSavedSearchesConstants Constant
hi def link confSavedSearchesDeprecated Removed
