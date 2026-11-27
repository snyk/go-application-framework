package hook

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/contributors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
	networktypes "github.com/snyk/go-application-framework/pkg/networking/network_types"
)

type countingNetworkAccess struct {
	networking.NetworkAccess
	added atomic.Int32
}

func (c *countingNetworkAccess) AddMiddleware(m networktypes.MiddlewareFunc) {
	c.added.Add(1)
	c.NetworkAccess.AddMiddleware(m)
}

func newCountingNA(cfg configuration.Configuration) *countingNetworkAccess {
	return &countingNetworkAccess{NetworkAccess: networking.NewNetworkAccess(cfg)}
}

func Test_activator_setup_concurrentBothGetMiddleware(t *testing.T) {
	logger := zerolog.Nop()
	act := &activator{sink: &contributors.Sink{}, logger: &logger}

	var lookups atomic.Int32
	cfg := configuration.NewInMemory()
	cfg.Set(configuration.API_URL, "https://api.example")
	cfg.Set(configuration.AUTHENTICATION_TOKEN, "shared-token")
	cfg.AddDefaultValue(configEnableEntityContributorsPublish, func(_ configuration.Configuration, existing any) (any, error) {
		if existing != nil {
			return existing, nil
		}
		lookups.Add(1)
		time.Sleep(20 * time.Millisecond)
		return true, nil
	})

	const n = 8
	accesses := make([]*countingNetworkAccess, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			na := newCountingNA(configuration.NewInMemory())
			na.SetConfiguration(cfg)
			act.setup(na, cfg)
			accesses[i] = na
		}(i)
	}
	wg.Wait()

	for i, na := range accesses {
		require.NotNil(t, na)
		assert.Equal(t, int32(1), na.added.Load(), "invoke %d must receive capture middleware", i)
	}
	assert.GreaterOrEqual(t, lookups.Load(), int32(1))
}

func Test_activator_setup_flagLookupErrorDoesNotEnable(t *testing.T) {
	logger := zerolog.Nop()
	act := &activator{sink: &contributors.Sink{}, logger: &logger}

	var lookups atomic.Int32
	cfg := configuration.NewInMemory()
	cfg.Set(configuration.API_URL, "https://api.example")
	cfg.Set(configuration.AUTHENTICATION_TOKEN, "tok")
	cfg.AddDefaultValue(configEnableEntityContributorsPublish, func(_ configuration.Configuration, existing any) (any, error) {
		if existing != nil {
			return existing, nil
		}
		n := lookups.Add(1)
		if n == 1 {
			return false, assert.AnError
		}
		return true, nil
	})

	first := newCountingNA(configuration.NewInMemory())
	first.SetConfiguration(cfg)
	act.setup(first, cfg)
	assert.Equal(t, int32(0), first.added.Load(), "failed lookup must not enable capture")

	second := newCountingNA(configuration.NewInMemory())
	second.SetConfiguration(cfg)
	act.setup(second, cfg)
	assert.Equal(t, int32(1), second.added.Load(), "successful retry must enable capture")
	assert.Equal(t, int32(2), lookups.Load())
}

func Test_activator_setup_differentOrgsDoNotShareDecision(t *testing.T) {
	logger := zerolog.Nop()
	act := &activator{sink: &contributors.Sink{}, logger: &logger}

	makeCfg := func(org string, flag bool) configuration.Configuration {
		cfg := configuration.NewInMemory()
		cfg.Set(configuration.API_URL, "https://api.example")
		cfg.Set(configuration.AUTHENTICATION_TOKEN, "same-token")
		cfg.Set(configuration.ORGANIZATION, org)
		cfg.Set(configEnableEntityContributorsPublish, flag)
		return cfg
	}

	on := newCountingNA(configuration.NewInMemory())
	onCfg := makeCfg("11111111-1111-1111-1111-111111111111", true)
	on.SetConfiguration(onCfg)
	act.setup(on, onCfg)
	assert.Equal(t, int32(1), on.added.Load())

	off := newCountingNA(configuration.NewInMemory())
	offCfg := makeCfg("22222222-2222-2222-2222-222222222222", false)
	off.SetConfiguration(offCfg)
	act.setup(off, offCfg)
	assert.Equal(t, int32(0), off.added.Load(), "org B must not inherit org A's enabled decision")
}
