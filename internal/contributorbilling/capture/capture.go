package capture

import (
	"context"
	"sync"
)

type contextKey struct{}

// Capability identifies the CLI product flow that produced a captured billing entity.
type Capability string

const (
	CapabilityOSS  Capability = "oss"
	CapabilityIaC  Capability = "iac"
	CapabilityCode Capability = "code"
)

// EntityTypeProject is the default ES ingest entity prefix for Registry project public IDs.
const EntityTypeProject = "project"

// Record holds one billing entity observed from a successful product API interaction.
type Record struct {
	Capability  Capability
	EntityID    string
	EntityType  string
	RequestPath string
}

type billableTest struct {
	capability Capability
}

// Capture accumulates billing entities for the current CLI interaction.
type Capture struct {
	mu            sync.Mutex
	records       []Record
	billableTests map[string]billableTest
}

// NewCapture returns an empty capture bag.
func NewCapture() *Capture {
	return &Capture{
		billableTests: make(map[string]billableTest),
	}
}

// Add appends a record when entityID is non-empty.
func (c *Capture) Add(record Record) {
	if c == nil || record.EntityID == "" {
		return
	}
	if record.EntityType == "" {
		record.EntityType = EntityTypeProject
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, record)
}

// RegisterBillableTest marks a Test API test ID as eligible for capture on follow-up GETs.
func (c *Capture) RegisterBillableTest(testID string, capability Capability) {
	if c == nil || testID == "" || capability == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.billableTests == nil {
		c.billableTests = make(map[string]billableTest)
	}
	c.billableTests[testID] = billableTest{capability: capability}
}

// BillableTestCapability returns the capability registered for testID, if any.
func (c *Capture) BillableTestCapability(testID string) (Capability, bool) {
	if c == nil || testID == "" {
		return "", false
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	meta, ok := c.billableTests[testID]
	if !ok {
		return "", false
	}
	return meta.capability, true
}

// Snapshot returns a copy of captured records.
func (c *Capture) Snapshot() []Record {
	if c == nil {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.records) == 0 {
		return nil
	}

	out := make([]Record, len(c.records))
	copy(out, c.records)
	return out
}

// DedupedRecords returns captured records deduplicated by capability, entity type, and entity ID,
// preserving first-seen order.
func (c *Capture) DedupedRecords() []Record {
	snapshot := c.Snapshot()
	if len(snapshot) == 0 {
		return nil
	}

	type dedupeKey struct {
		capability Capability
		entityType string
		entityID   string
	}

	seen := make(map[dedupeKey]Record, len(snapshot))
	order := make([]dedupeKey, 0, len(snapshot))
	for _, record := range snapshot {
		entityType := record.EntityType
		if entityType == "" {
			entityType = EntityTypeProject
		}
		key := dedupeKey{capability: record.Capability, entityType: entityType, entityID: record.EntityID}
		if _, exists := seen[key]; exists {
			continue
		}
		record.EntityType = entityType
		seen[key] = record
		order = append(order, key)
	}

	out := make([]Record, 0, len(order))
	for _, key := range order {
		out = append(out, seen[key])
	}
	return out
}

// WithCapture attaches capture to ctx for contributor billing middleware to populate.
func WithCapture(ctx context.Context, bag *Capture) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, contextKey{}, bag)
}

// FromContext returns the capture bag attached to ctx, or nil.
func FromContext(ctx context.Context) *Capture {
	if ctx == nil {
		return nil
	}

	bag, ok := ctx.Value(contextKey{}).(*Capture)
	if !ok {
		return nil
	}
	return bag
}
