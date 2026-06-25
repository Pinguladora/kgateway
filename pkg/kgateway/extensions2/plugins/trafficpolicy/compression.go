package trafficpolicy

import (
	"fmt"
	"hash/fnv"
	"strconv"

	envoycorev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	brotlicompressorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/compression/brotli/compressor/v3"
	gzipcompressorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/compression/gzip/compressor/v3"
	gzipdecompressorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/compression/gzip/decompressor/v3"
	zstdcompressorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/compression/zstd/compressor/v3"
	compressorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/compressor/v3"
	decompressorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/decompressor/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"
	"github.com/kgateway-dev/kgateway/v2/pkg/kgateway/utils"
	"github.com/kgateway-dev/kgateway/v2/pkg/pluginsdk/filters"
	"github.com/kgateway-dev/kgateway/v2/pkg/pluginsdk/ir"
)

const (
	compressorFilterName   = "envoy.filters.http.compressor"
	decompressorFilterName = "envoy.filters.http.decompressor"
)

type compressionIR struct {
	enable bool
	// libraries are the response compression codecs to offer, in preference order.
	// Only meaningful when enable is true.
	libraries []kgateway.CompressionLibrary
}

type decompressionIR struct {
	enable bool
}

var (
	_ PolicySubIR = &compressionIR{}
	_ PolicySubIR = &decompressionIR{}
)

func (c *compressionIR) Equals(other PolicySubIR) bool {
	oc, ok := other.(*compressionIR)
	if !ok {
		return false
	}
	if c == nil || oc == nil {
		return c == nil && oc == nil
	}
	if c.enable != oc.enable {
		return false
	}
	// When disabled, all codecs are turned off regardless of libraries.
	if !c.enable {
		return true
	}
	if len(c.libraries) != len(oc.libraries) {
		return false
	}
	for i := range c.libraries {
		if c.libraries[i] != oc.libraries[i] {
			return false
		}
	}
	return true
}

func (c *compressionIR) Validate() error { return nil }

func (d *decompressionIR) Equals(other PolicySubIR) bool {
	od, ok := other.(*decompressionIR)
	if !ok {
		return false
	}
	if d == nil || od == nil {
		return d == nil && od == nil
	}
	return d.enable == od.enable
}

func (d *decompressionIR) Validate() error { return nil }

// constructCompression builds IR for response compression (per-route) and decompression (listener enable toggle).
func constructCompression(spec kgateway.TrafficPolicySpec, out *trafficPolicySpecIr) {
	if spec.Compression == nil {
		return
	}

	// Enable response compression if not disabled
	if rc := spec.Compression.ResponseCompression; rc != nil {
		// Default to gzip for backward compatibility when no codec is selected.
		// Note: we intentionally rely on Envoy defaults for the codec config and content types.
		libraries := rc.Libraries
		if len(libraries) == 0 {
			libraries = []kgateway.CompressionLibrary{kgateway.CompressionGzip}
		}
		out.compression = &compressionIR{enable: (rc.Disable == nil), libraries: libraries}
	}

	// Enable request decompression if not disabled
	if dc := spec.Compression.RequestDecompression; dc != nil {
		out.decompression = &decompressionIR{enable: (dc.Disable == nil)}
	}
}

// compressorEntry is a single codec's compressor filter installed in a filter chain.
type compressorEntry struct {
	// filterName is the unique HTTP filter name for this compressor.
	filterName string
	compressor *compressorv3.Compressor
}

// allCompressionLibraries lists every supported response compression codec. Used on the
// disable path to turn off every codec a higher-level policy might have enabled.
var allCompressionLibraries = []kgateway.CompressionLibrary{
	kgateway.CompressionGzip,
	kgateway.CompressionBrotli,
	kgateway.CompressionZstd,
}

func (p *trafficPolicyPluginGwPass) handleCompression(fcn string, pCtxTypedFilterConfig *ir.TypedFilterConfigMap, comp *compressionIR) {
	if comp == nil {
		return
	}

	// Disable path: the route turns compression off. The codecs enabled by a higher-level
	// policy are not known here, so disable every codec's compressor filter and mark the
	// per-route config optional so Envoy ignores codecs absent from the chain.
	if !comp.enable {
		for _, library := range allCompressionLibraries {
			pCtxTypedFilterConfig.AddTypedConfig(compressorFilterNameFor(library), DisableFilterPerRouteOptional())
		}
		return
	}

	if p.compressorInChain == nil {
		p.compressorInChain = make(map[string][]compressorEntry)
	}
	// Routes share one filter chain and Envoy decides q-value ties via the compressor's
	// choose_first flag, not filter order. Key multi-codec filters per ordered list (so per-route
	// choose_first can't leak between routes) and mark the first codec choose_first so it wins ties.
	for i, library := range comp.libraries {
		filterName := compressorFilterNameForList(library, comp.libraries)
		pCtxTypedFilterConfig.AddTypedConfig(filterName, EnableFilterPerRoute())

		if !hasCompressorNamed(p.compressorInChain[fcn], filterName) {
			chooseFirst := len(comp.libraries) > 1 && i == 0
			p.compressorInChain[fcn] = append(p.compressorInChain[fcn], compressorEntry{
				filterName: filterName,
				compressor: newCompressor(library, chooseFirst),
			})
		}
	}
}

// compressorFilterNameForList names a codec's filter; multi-codec lists append a hash of the
// ordered list so routes with differing preferences get distinct filters.
func compressorFilterNameForList(library kgateway.CompressionLibrary, libraries []kgateway.CompressionLibrary) string {
	base := compressorFilterNameFor(library)
	if len(libraries) <= 1 {
		return base
	}
	return base + "." + listHash(libraries)
}

// compressorFilterNameFor returns the per-codec base name; gzip keeps the historical name for
// backward compatibility.
func compressorFilterNameFor(library kgateway.CompressionLibrary) string {
	switch library {
	case kgateway.CompressionBrotli:
		return compressorFilterName + ".brotli"
	case kgateway.CompressionZstd:
		return compressorFilterName + ".zstd"
	default: // CompressionGzip
		return compressorFilterName
	}
}

func listHash(libraries []kgateway.CompressionLibrary) string {
	h := fnv.New32a()
	for _, l := range libraries {
		fmt.Fprintf(h, "%s;", l)
	}
	return strconv.FormatUint(uint64(h.Sum32()), 16)
}

func hasCompressorNamed(entries []compressorEntry, filterName string) bool {
	for i := range entries {
		if entries[i].filterName == filterName {
			return true
		}
	}
	return false
}

// newCompressor builds a disabled baseline compressor filter for the given codec, using
// Envoy defaults for the codec config (no quality/level knobs).
func newCompressor(library kgateway.CompressionLibrary, chooseFirst bool) *compressorv3.Compressor {
	return &compressorv3.Compressor{
		RequestDirectionConfig: &compressorv3.Compressor_RequestDirectionConfig{
			CommonConfig: &compressorv3.Compressor_CommonDirectionConfig{
				Enabled: &envoycorev3.RuntimeFeatureFlag{
					DefaultValue: wrapperspb.Bool(false),
				},
			},
		},
		CompressorLibrary: compressorLibraryFor(library),
		ChooseFirst:       chooseFirst,
	}
}

// compressorLibraryFor returns the Envoy compressor library extension config for the given
// codec. The typed config is left at Envoy defaults (no quality/level knobs).
func compressorLibraryFor(library kgateway.CompressionLibrary) *envoycorev3.TypedExtensionConfig {
	switch library {
	case kgateway.CompressionBrotli:
		brotliAny, _ := utils.MessageToAny(&brotlicompressorv3.Brotli{})
		return &envoycorev3.TypedExtensionConfig{
			Name:        "envoy.compression.brotli.compressor",
			TypedConfig: brotliAny,
		}
	case kgateway.CompressionZstd:
		zstdAny, _ := utils.MessageToAny(&zstdcompressorv3.Zstd{})
		return &envoycorev3.TypedExtensionConfig{
			Name:        "envoy.compression.zstd.compressor",
			TypedConfig: zstdAny,
		}
	default: // CompressionGzip and unset both map to gzip for backward compatibility.
		gzipAny, _ := utils.MessageToAny(&gzipcompressorv3.Gzip{})
		return &envoycorev3.TypedExtensionConfig{
			Name:        "envoy.compression.gzip.compressor",
			TypedConfig: gzipAny,
		}
	}
}

func (p *trafficPolicyPluginGwPass) handleDecompression(fcn string, pCtxTypedFilterConfig *ir.TypedFilterConfigMap, decomp *decompressionIR) {
	if decomp == nil {
		return
	}
	if decomp.enable {
		pCtxTypedFilterConfig.AddTypedConfig(decompressorFilterName, EnableFilterPerRoute())
	} else {
		pCtxTypedFilterConfig.AddTypedConfig(decompressorFilterName, DisableFilterPerRoute())
		return
	}
	if p.decompressorInChain == nil {
		p.decompressorInChain = make(map[string]*decompressorv3.Decompressor)
	}
	if _, ok := p.decompressorInChain[fcn]; !ok {
		gzipAny, _ := utils.MessageToAny(&gzipdecompressorv3.Gzip{})
		p.decompressorInChain[fcn] = &decompressorv3.Decompressor{
			ResponseDirectionConfig: &decompressorv3.Decompressor_ResponseDirectionConfig{
				CommonConfig: &decompressorv3.Decompressor_CommonDirectionConfig{
					Enabled: &envoycorev3.RuntimeFeatureFlag{
						DefaultValue: wrapperspb.Bool(false),
					},
				},
			},
			DecompressorLibrary: &envoycorev3.TypedExtensionConfig{
				Name:        "envoy.compression.gzip.decompressor",
				TypedConfig: gzipAny,
			},
		}
	}
}

// HttpFilters wiring is in traffic_policy_plugin.go
func addCompressionFiltersIfNeeded(staged []filters.StagedHttpFilter, p *trafficPolicyPluginGwPass, fcn string) []filters.StagedHttpFilter {
	// Emit one compressor filter per codec. Filters of differing types in the same stage are
	// otherwise ordered by name, which would not reflect the configured preference; place each
	// codec at an increasing weight after the CORS stage so chain order follows preference
	// order (earlier = higher tie-break priority for Accept-Encoding negotiation). A single
	// gzip codec lands at weight 1, identical to the previous AfterStage(CorsStage) placement.
	for i, entry := range p.compressorInChain[fcn] {
		filter := filters.MustNewStagedFilter(
			entry.filterName,
			entry.compressor,
			filters.RelativeToStage(filters.WellKnownFilterStage(filters.CorsStage), 1+i),
		)
		filter.Filter.Disabled = true
		staged = append(staged, filter)
	}
	if d := p.decompressorInChain[fcn]; d != nil {
		filter := filters.MustNewStagedFilter(
			decompressorFilterName,
			d,
			filters.AfterStage(filters.WellKnownFilterStage(filters.CorsStage)),
		)
		filter.Filter.Disabled = true
		staged = append(staged, filter)
	}
	return staged
}
