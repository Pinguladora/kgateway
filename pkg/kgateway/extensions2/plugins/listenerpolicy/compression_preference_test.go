package listenerpolicy

import (
	"testing"

	compressorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/compressor/v3"
	envoy_hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"
	"github.com/kgateway-dev/kgateway/v2/pkg/kgateway/utils"
)

func compressorHTTPFilter(t *testing.T, name string) *envoy_hcm.HttpFilter {
	t.Helper()
	cfg, err := utils.MessageToAny(&compressorv3.Compressor{})
	require.NoError(t, err)
	return &envoy_hcm.HttpFilter{Name: name, ConfigType: &envoy_hcm.HttpFilter_TypedConfig{TypedConfig: cfg}}
}

func filterNames(fs []*envoy_hcm.HttpFilter) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.GetName()
	}
	return out
}

func filterChooseFirst(t *testing.T, f *envoy_hcm.HttpFilter) bool {
	t.Helper()
	var c compressorv3.Compressor
	require.NoError(t, f.GetTypedConfig().UnmarshalTo(&c))
	return c.GetChooseFirst()
}

func TestApplyResponseCompressionCodecPreference(t *testing.T) {
	const gzip = compressorFilterName
	const brotli = compressorFilterName + ".brotli"
	const zstd = compressorFilterName + ".zstd"
	const router = "envoy.filters.http.router"

	t.Run("orders most preferred last and sets choose_first on preferred codecs", func(t *testing.T) {
		hcm := &envoy_hcm.HttpConnectionManager{HttpFilters: []*envoy_hcm.HttpFilter{
			compressorHTTPFilter(t, brotli),
			compressorHTTPFilter(t, gzip),
			compressorHTTPFilter(t, zstd),
			compressorHTTPFilter(t, router),
		}}
		require.NoError(t, applyResponseCompressionCodecPreference(hcm, []kgateway.CompressionLibrary{
			kgateway.CompressionZstd, kgateway.CompressionBrotli, kgateway.CompressionGzip,
		}))
		// Most preferred (zstd) is last among the compressors, router keeps its position.
		assert.Equal(t, []string{gzip, brotli, zstd, router}, filterNames(hcm.GetHttpFilters()))
		for _, f := range hcm.GetHttpFilters()[:3] {
			assert.True(t, filterChooseFirst(t, f), "choose_first on %s", f.GetName())
		}
	})

	t.Run("empty preference is a no-op", func(t *testing.T) {
		hcm := &envoy_hcm.HttpConnectionManager{HttpFilters: []*envoy_hcm.HttpFilter{
			compressorHTTPFilter(t, brotli),
			compressorHTTPFilter(t, gzip),
		}}
		require.NoError(t, applyResponseCompressionCodecPreference(hcm, nil))
		assert.Equal(t, []string{brotli, gzip}, filterNames(hcm.GetHttpFilters()))
		assert.False(t, filterChooseFirst(t, hcm.GetHttpFilters()[0]))
	})

	t.Run("single codec is a no-op", func(t *testing.T) {
		hcm := &envoy_hcm.HttpConnectionManager{HttpFilters: []*envoy_hcm.HttpFilter{
			compressorHTTPFilter(t, gzip),
		}}
		require.NoError(t, applyResponseCompressionCodecPreference(hcm, []kgateway.CompressionLibrary{kgateway.CompressionZstd}))
		assert.False(t, filterChooseFirst(t, hcm.GetHttpFilters()[0]))
	})

	t.Run("codec absent from preference keeps client order and no choose_first", func(t *testing.T) {
		hcm := &envoy_hcm.HttpConnectionManager{HttpFilters: []*envoy_hcm.HttpFilter{
			compressorHTTPFilter(t, gzip),
			compressorHTTPFilter(t, zstd),
		}}
		require.NoError(t, applyResponseCompressionCodecPreference(hcm, []kgateway.CompressionLibrary{kgateway.CompressionZstd}))
		// zstd is preferred so it sorts last with choose_first; gzip is unlisted, stays first without it.
		assert.Equal(t, []string{gzip, zstd}, filterNames(hcm.GetHttpFilters()))
		assert.False(t, filterChooseFirst(t, hcm.GetHttpFilters()[0]))
		assert.True(t, filterChooseFirst(t, hcm.GetHttpFilters()[1]))
	})
}
