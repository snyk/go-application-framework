package configuration

import (
	"testing"
	"time"
)

// BenchmarkGet_NoCaching measures Get() without caching (getCacheSettings returns early on nil cache).
func BenchmarkGet_NoCaching(b *testing.B) {
	config := NewWithOpts(WithAutomaticEnv())
	config.Set("bench_key", "bench_value")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = config.Get("bench_key")
	}
}

// BenchmarkGet_CachingEnabled measures Get() with caching enabled (getCacheSettings reads two keys via ev.get()).
func BenchmarkGet_CachingEnabled(b *testing.B) {
	config := NewWithOpts(WithAutomaticEnv(), WithCachingEnabled(5*time.Minute))
	config.Set("bench_key", "bench_value")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = config.Get("bench_key")
	}
}

// BenchmarkGet_CachingEnabled_CacheHit measures Get() when the value is already cached.
func BenchmarkGet_CachingEnabled_CacheHit(b *testing.B) {
	config := NewWithOpts(WithAutomaticEnv(), WithCachingEnabled(5*time.Minute))
	config.AddDefaultValue("bench_cached", StandardDefaultValueFunction("computed"))
	// Prime the cache
	_ = config.Get("bench_cached")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = config.Get("bench_cached")
	}
}

// BenchmarkGet_CachingEnabled_CacheMiss measures Get() with cache enabled but value set via Set() (not cached by default func).
func BenchmarkGet_CachingEnabled_CacheMiss(b *testing.B) {
	config := NewWithOpts(WithAutomaticEnv(), WithCachingEnabled(5*time.Minute))
	config.Set("bench_miss", "direct_value")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = config.Get("bench_miss")
	}
}

// BenchmarkGetWithError_CachingEnabled measures GetWithError() with caching — the full hot path including getCacheSettings.
func BenchmarkGetWithError_CachingEnabled(b *testing.B) {
	config := NewWithOpts(WithAutomaticEnv(), WithCachingEnabled(5*time.Minute))
	config.Set("bench_key", "bench_value")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = config.GetWithError("bench_key")
	}
}

// BenchmarkGetString_CachingEnabled measures GetString() with caching.
func BenchmarkGetString_CachingEnabled(b *testing.B) {
	config := NewWithOpts(WithAutomaticEnv(), WithCachingEnabled(5*time.Minute))
	config.Set("bench_str", "hello")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = config.GetString("bench_str")
	}
}

// BenchmarkGetBool_CachingEnabled measures GetBool() with caching.
func BenchmarkGetBool_CachingEnabled(b *testing.B) {
	config := NewWithOpts(WithAutomaticEnv(), WithCachingEnabled(5*time.Minute))
	config.Set("bench_bool", true)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = config.GetBool("bench_bool")
	}
}

// BenchmarkGet_WithPrefixEnvVars measures Get() with prefix-based env var support (exercises getKeyType + bindEnv path).
func BenchmarkGet_WithPrefixEnvVars(b *testing.B) {
	config := NewWithOpts(WithSupportedEnvVarPrefixes("snyk_"), WithCachingEnabled(5*time.Minute))
	config.Set("snyk_token", "test-token")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = config.Get("snyk_token")
	}
}

// BenchmarkGetCacheSettings_Parallel measures getCacheSettings under concurrent access.
func BenchmarkGetCacheSettings_Parallel(b *testing.B) {
	config := NewWithOpts(WithAutomaticEnv(), WithCachingEnabled(5*time.Minute))
	config.Set("bench_par", "value")

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = config.Get("bench_par")
		}
	})
}
