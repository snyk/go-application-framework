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

func Test_activator_setup_concurrentSameKeyBothGetMiddleware(t *testing.T) {
	logger := zerolog.Nop()
	act := &activator{
		sink:    &contributors.Sink{},
		logger:  &logger,
		enabled: make(map[string]bool),
	}

	var lookups atomic.Int32
	cfg := configuration.NewInMemory()
	cfg.Set(configuration.API_URL, "https://api.example")
	cfg.Set(configuration.AUTHENTICATION_TOKEN, "shared-token")
	cfg.AddDefaultValue(configEnableEntityContributorsPublish, func(_ configuration.Configuration, existing any) (any, error) {
		if existing != nil {
			return existing, nil
		}
		lookups.Add(1)
		time.Sleep(50 * time.Millisecond)
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

	assert.Equal(t, int32(1), lookups.Load(), "flag must resolve once for the same credentials")
	for i, na := range accesses {
		require.NotNil(t, na)
		assert.Equal(t, int32(1), na.added.Load(), "invoke %d must receive capture middleware", i)
	}
}

func Test_activator_setup_flagLookupErrorIsRetried(t *testing.T) {
	logger := zerolog.Nop()
	act := &activator{
		sink:    &contributors.Sink{},
		logger:  &logger,
		enabled: make(map[string]bool),
	}

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
