package listenerpolicy

import (
	"slices"
	"strings"

	compressorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/compressor/v3"
	envoy_hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"

	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"
	"github.com/kgateway-dev/kgateway/v2/pkg/kgateway/utils"
)

// compressorFilterName is the base name of the Envoy response compressor filter. Per-codec filters
// append a suffix. This must stay in sync with the naming scheme in the trafficpolicy plugin
// (trafficpolicy/compression.go), which is the plugin that installs the compressor filters.
const compressorFilterName = "envoy.filters.http.compressor"

// applyResponseCompressionCodecPreference reorders the compressor filters already installed on the
// HCM so the most preferred codec is last, and sets choose_first on each preferred codec. Envoy
// chooses the last choose_first codec the client accepts, so the most preferred accepted codec wins
// when Accept-Encoding weights are equal. Non-compressor filters keep their positions, and codecs
// absent from the preference keep the client's ordering.
func applyResponseCompressionCodecPreference(out *envoy_hcm.HttpConnectionManager, preference []kgateway.CompressionLibrary) error {
	if len(preference) == 0 {
		return nil
	}
	httpFilters := out.GetHttpFilters()

	// Slots holding compressor filters, in their current order.
	var slots []int
	for i, f := range httpFilters {
		if isCompressorFilter(f.GetName()) {
			slots = append(slots, i)
		}
	}
	// A preference only matters when the chain offers more than one codec.
	if len(slots) <= 1 {
		return nil
	}

	// rank is higher for more preferred codecs, so the most preferred sorts last. Codecs absent
	// from the preference get 0 and sort first, keeping the client's ordering for them.
	rank := make(map[kgateway.CompressionLibrary]int, len(preference))
	for i, lib := range preference {
		rank[lib] = len(preference) - i
	}

	comps := make([]*envoy_hcm.HttpFilter, 0, len(slots))
	for _, i := range slots {
		comps = append(comps, httpFilters[i])
	}

	// Set choose_first on each codec named in the preference.
	for _, f := range comps {
		if rank[libraryForCompressorFilterName(f.GetName())] > 0 {
			if err := setChooseFirst(f); err != nil {
				return err
			}
		}
	}

	// Order the compressor filters so the most preferred codec is last.
	slices.SortStableFunc(comps, func(a, b *envoy_hcm.HttpFilter) int {
		return rank[libraryForCompressorFilterName(a.GetName())] - rank[libraryForCompressorFilterName(b.GetName())]
	})

	// Write the reordered filters back into the same slots, leaving other filters untouched.
	for j, i := range slots {
		httpFilters[i] = comps[j]
	}
	return nil
}

// isCompressorFilter reports whether an HCM filter name is a response compressor filter. The
// decompressor filter has a different base name, so it is not matched.
func isCompressorFilter(name string) bool {
	return name == compressorFilterName || strings.HasPrefix(name, compressorFilterName+".")
}

// libraryForCompressorFilterName maps a compressor filter name back to its codec.
func libraryForCompressorFilterName(name string) kgateway.CompressionLibrary {
	switch {
	case strings.Contains(name, ".brotli"):
		return kgateway.CompressionBrotli
	case strings.Contains(name, ".zstd"):
		return kgateway.CompressionZstd
	default:
		return kgateway.CompressionGzip
	}
}

// setChooseFirst sets choose_first on a compressor filter's typed config.
func setChooseFirst(f *envoy_hcm.HttpFilter) error {
	tc := f.GetTypedConfig()
	if tc == nil {
		return nil
	}
	var comp compressorv3.Compressor
	if err := tc.UnmarshalTo(&comp); err != nil {
		return err
	}
	comp.ChooseFirst = true
	newAny, err := utils.MessageToAny(&comp)
	if err != nil {
		return err
	}
	f.ConfigType = &envoy_hcm.HttpFilter_TypedConfig{TypedConfig: newAny}
	return nil
}
