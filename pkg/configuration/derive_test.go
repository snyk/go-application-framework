package configuration

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Derive(t *testing.T) {
	newBase := func(t *testing.T) *extendedViper {
		t.Helper()
		t.Setenv("DERIVE_TEST_ENV", "fromenv")
		base := NewWithOpts(WithAutomaticEnv(), WithPinnedFile(filepath.Join(t.TempDir(), "base.json")), WithCachingEnabled(NoCacheExpiration))
		fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
		fs.String("flagkey", "", "")
		require.NoError(t, base.AddFlagSet(fs))
		base.AddDefaultValue("defkey", StandardDefaultValueFunction("default"))
		base.AddAlternativeKeys("main", []string{"alt"})
		require.NoError(t, base.AddKeyDependency("child", "parent"))
		base.PersistInStorage("persisted")
		return asViper(t, base)
	}

	t.Run("carries registrations but no values", func(t *testing.T) {
		base := newBase(t)
		base.Set("value", "basevalue")
		base.Set("alt", "altvalue")
		require.NoError(t, base.flagsets[0].Set("flagkey", "flagvalue"))
		assert.Equal(t, "flagvalue", base.GetString("flagkey"))
		assert.Equal(t, "altvalue", base.GetString("main"))

		file := filepath.Join(t.TempDir(), "d.json")
		d, err := Derive(base, WithPinnedFile(file))
		require.NoError(t, err)

		assert.Equal(t, "default", d.GetString("defkey"))
		assert.Empty(t, d.GetString("value"))
		assert.Equal(t, "flagvalue", d.GetString("flagkey"), "flag objects are shared with base")
		assert.Empty(t, d.GetString("main"))
		d.Set("alt", "x")
		assert.Equal(t, "x", d.GetString("main"))
		assert.Equal(t, []string{"child"}, asViper(t, d).interkeyDependencies["parent"])
		assert.True(t, asViper(t, d).persistedKeys["persisted"])
		assert.NotNil(t, asViper(t, d).defaultCache)
		assert.NotSame(t, base.GetStorage(), d.GetStorage())
	})

	t.Run("reads the environment like the base, also when derived again or cloned", func(t *testing.T) {
		base := newBase(t)
		d, err := Derive(base, WithPinnedFile(filepath.Join(t.TempDir(), "d.json")))
		require.NoError(t, err)
		again, err := Derive(d, WithPinnedFile(filepath.Join(t.TempDir(), "again.json")))
		require.NoError(t, err)

		for _, c := range []Configuration{d, again, d.Clone()} {
			assert.True(t, c.GetAutomaticEnv())
			assert.Equal(t, "fromenv", c.GetString("derive_test_env"))
		}
	})

	t.Run("no automatic env in base, no env read", func(t *testing.T) {
		t.Setenv("DERIVE_TEST_NOAUTO", "fromenv")
		base := NewWithOpts(WithPinnedFile(filepath.Join(t.TempDir(), "base.json")))
		d, err := Derive(base, WithPinnedFile(filepath.Join(t.TempDir(), "d.json")))
		require.NoError(t, err)

		assert.False(t, d.GetAutomaticEnv())
		assert.Empty(t, d.GetString("derive_test_noauto"))
	})

	t.Run("supported env vars of base are read and options of Derive are kept", func(t *testing.T) {
		t.Setenv("DERIVE_TEST_SUPPORTED", "from-base-list")
		t.Setenv("DERIVE_TEST_OPTION", "from-option-list")
		base := NewWithOpts(WithSupportedEnvVars("DERIVE_TEST_SUPPORTED"), WithPinnedFile(filepath.Join(t.TempDir(), "base.json")))

		d, err := Derive(base, WithPinnedFile(filepath.Join(t.TempDir(), "d.json")), WithSupportedEnvVars("DERIVE_TEST_OPTION"))
		require.NoError(t, err)
		assert.Equal(t, "from-base-list", d.GetString("derive_test_supported"))
		assert.Equal(t, "from-option-list", d.GetString("derive_test_option"))
		assert.ElementsMatch(t, []string{"DERIVE_TEST_OPTION", "DERIVE_TEST_SUPPORTED"}, d.GetSupportedEnvVars())
	})

	t.Run("changes made on derived do not reach base", func(t *testing.T) {
		base := newBase(t)
		d, err := Derive(base, WithPinnedFile(filepath.Join(t.TempDir(), "d.json")))
		require.NoError(t, err)

		d.Set("only", "derived")
		assert.Empty(t, base.GetString("only"))
		d.AddAlternativeKeys("main", []string{"other"})
		d.AddDefaultValue("defkey", StandardDefaultValueFunction("changed"))
		assert.Equal(t, []string{"alt"}, base.GetAlternativeKeys("main"))
		assert.Equal(t, "default", base.GetString("defkey"))
	})

	t.Run("registrations added to base after Derive are not seen", func(t *testing.T) {
		base := newBase(t)
		d, err := Derive(base, WithPinnedFile(filepath.Join(t.TempDir(), "d.json")))
		require.NoError(t, err)

		base.AddAlternativeKeys("late", []string{"late_alt"})
		base.AddDefaultValue("latedef", StandardDefaultValueFunction("latevalue"))
		require.NoError(t, base.AddKeyDependency("latechild", "lateparent"))
		base.PersistInStorage("latepersisted")
		lateFlags := pflag.NewFlagSet("late", pflag.ContinueOnError)
		lateFlags.String("lateflag", "", "")
		require.NoError(t, base.AddFlagSet(lateFlags))

		assert.Empty(t, d.GetAlternativeKeys("late"))
		assert.Empty(t, d.GetString("latedef"))
		assert.Empty(t, asViper(t, d).interkeyDependencies["lateparent"])
		assert.False(t, asViper(t, d).persistedKeys["latepersisted"])
		require.NoError(t, lateFlags.Set("lateflag", "latevalue"))
		assert.Equal(t, "latevalue", base.GetString("lateflag"))
		assert.Empty(t, d.GetString("lateflag"))
	})

	t.Run("in place changes of base slices after Derive are not seen", func(t *testing.T) {
		base := newBase(t)
		d, err := Derive(base, WithPinnedFile(filepath.Join(t.TempDir(), "d.json")))
		require.NoError(t, err)

		base.GetAlternativeKeys("main")[0] = "changed"
		asViper(t, base).interkeyDependencies["parent"][0] = "changed"

		assert.Equal(t, []string{"alt"}, d.GetAlternativeKeys("main"))
		assert.Equal(t, []string{"child"}, asViper(t, d).interkeyDependencies["parent"])
	})

	t.Run("supported env vars are merged without duplicates", func(t *testing.T) {
		base := NewWithOpts(WithSupportedEnvVars("A", "B"))
		d, err := Derive(base, WithSupportedEnvVars("B", "C"))
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"A", "B", "C"}, d.GetSupportedEnvVars())
	})

	t.Run("cache disabled value of base is not copied", func(t *testing.T) {
		base := NewWithOpts(WithCachingEnabled(time.Hour))
		base.Set(CONFIG_CACHE_DISABLED, true)
		d, err := Derive(base)
		require.NoError(t, err)

		baseEnabled, _ := asViper(t, base).getCacheSettings()
		derivedEnabled, _ := asViper(t, d).getCacheSettings()
		assert.False(t, baseEnabled)
		assert.True(t, derivedEnabled)
	})

	t.Run("can derive from a clone", func(t *testing.T) {
		base := newBase(t)
		d, err := Derive(base.Clone(), WithPinnedFile(filepath.Join(t.TempDir(), "d.json")))
		require.NoError(t, err)
		assert.Equal(t, "default", d.GetString("defkey"))
		assert.Equal(t, []string{"child"}, asViper(t, d).interkeyDependencies["parent"])
	})

	t.Run("cache TTL of base is carried over", func(t *testing.T) {
		base := NewWithOpts(WithCachingEnabled(50*time.Millisecond), WithPinnedFile(filepath.Join(t.TempDir(), "base.json")))
		d, err := Derive(base, WithPinnedFile(filepath.Join(t.TempDir(), "d.json")))
		require.NoError(t, err)
		assert.NotNil(t, asViper(t, d).defaultCache)
		assert.Equal(t, 50*time.Millisecond, d.GetDuration(CONFIG_CACHE_TTL))
	})

	t.Run("cache option of the caller wins over the cache of base", func(t *testing.T) {
		base := NewWithOpts(WithCachingEnabled(time.Hour), WithPinnedFile(filepath.Join(t.TempDir(), "base.json")))
		d, err := Derive(base, WithPinnedFile(filepath.Join(t.TempDir(), "d.json")), WithCachingEnabled(time.Minute))
		require.NoError(t, err)
		assert.NotSame(t, asViper(t, base).defaultCache, asViper(t, d).defaultCache)
		assert.Equal(t, time.Minute, d.GetDuration(CONFIG_CACHE_TTL))
	})

	t.Run("cache option of the caller is used when base has no cache", func(t *testing.T) {
		base := NewWithOpts(WithPinnedFile(filepath.Join(t.TempDir(), "base.json")))
		d, err := Derive(base, WithPinnedFile(filepath.Join(t.TempDir(), "d.json")), WithCachingEnabled(time.Minute))
		require.NoError(t, err)
		assert.NotNil(t, asViper(t, d).defaultCache)
		assert.Equal(t, time.Minute, d.GetDuration(CONFIG_CACHE_TTL))
	})

	t.Run("WithFiles works as in NewWithOpts, without pinning", func(t *testing.T) {
		isolateHome(t)
		base := NewWithOpts()
		file := filepath.Join(t.TempDir(), "d.json")
		other := filepath.Join(t.TempDir(), "other.json")

		for _, opts := range [][]Opts{
			{WithFiles(file), WithFiles(other)},
			{WithFiles(file, "relative")},
		} {
			d, err := Derive(base, opts...)
			require.NoError(t, err)
			storage, ok := d.GetStorage().(*JsonStorage)
			require.True(t, ok)
			// createFileStorage joins with a slash, so both sides are cleaned
			assert.Equal(t, filepath.Clean(filepath.Join(determineBasePath(), "snyk.json")), filepath.Clean(storage.path))
		}
	})

	t.Run("rejects foreign implementations", func(t *testing.T) {
		_, err := Derive(nil)
		assert.ErrorContains(t, err, "cannot derive from configuration of type")

		_, err = Derive(foreignConfiguration{Configuration: NewInMemory()})
		require.Error(t, err)
		assert.ErrorContains(t, err, "cannot derive")
	})

	t.Run("checks the type of base before it reads any file", func(t *testing.T) {
		isolateHome(t)
		file := filepath.Join(t.TempDir(), "garbage")
		require.NoError(t, os.WriteFile(file, []byte("not json"), 0o644))
		logs := captureLog(t)

		_, err := Derive(foreignConfiguration{Configuration: NewInMemory()}, WithPinnedFile(file), WithCachingEnabled(time.Hour))
		require.Error(t, err)
		assert.ErrorContains(t, err, "cannot derive from configuration of type")
		assert.Empty(t, logs.String(), "the file is not read")
	})

	t.Run("options win over the registrations of base", func(t *testing.T) {
		base := newBase(t)
		optionDefault := func(c Configuration) {
			c.AddDefaultValue("defkey", ImmutableDefaultValueFunction("option"))
		}
		optionAlternatives := func(c Configuration) {
			c.AddAlternativeKeys("main", []string{"optalt"})
		}

		d, err := Derive(base, optionDefault, optionAlternatives)
		require.NoError(t, err)
		assert.Equal(t, "option", d.GetString("defkey"))
		assert.Equal(t, []string{"optalt"}, d.GetAlternativeKeys("main"))
	})

	t.Run("can run while base is changed concurrently", func(t *testing.T) {
		base := newBase(t)
		dir := t.TempDir()
		var wg sync.WaitGroup
		for range 2 {
			wg.Go(func() {
				for i := range 50 {
					base.Set("concurrent", i)
					base.AddAlternativeKeys("main", []string{"alt"})
					base.PersistInStorage("concurrent_persisted")
					base.AddDefaultValue("concurrent_default", ImmutableDefaultValueFunction(i))
					assert.NoError(t, base.AddKeyDependency("concurrent", "parent"))
				}
			})
			wg.Go(func() {
				for i := range 20 {
					_, err := Derive(base, WithPinnedFile(filepath.Join(dir, fmt.Sprintf("d%d.json", i))))
					assert.NoError(t, err)
				}
			})
		}
		wg.Wait()
	})
}

func Test_Derive_ConcurrentWritesToOneFileKeepEveryKey(t *testing.T) {
	isolateHome(t)
	file := filepath.Join(t.TempDir(), "shared.json")
	const writers, keysPerWriter = 4, 50
	base := NewWithOpts()
	for w := range writers {
		for i := range keysPerWriter {
			base.PersistInStorage(fmt.Sprintf("w%d_%d", w, i))
		}
	}

	var wg sync.WaitGroup
	for w := range writers {
		derived, err := Derive(base, WithPinnedFile(file))
		require.NoError(t, err)
		wg.Go(func() {
			for i := range keysPerWriter {
				derived.Set(fmt.Sprintf("w%d_%d", w, i), i)
			}
		})
	}
	wg.Wait()

	final := NewWithOpts(WithPinnedFile(file))
	for w := range writers {
		for i := range keysPerWriter {
			assert.Equal(t, i, final.GetInt(fmt.Sprintf("w%d_%d", w, i)), "a write from another configuration of the same file was lost")
		}
	}
}
