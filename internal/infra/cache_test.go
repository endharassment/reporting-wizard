package infra

import (
	"testing"
	"time"
)

func TestTTLCache_GetSet(t *testing.T) {
	c := newTTLCache[string, int](time.Hour)

	// Miss on empty cache.
	_, ok := c.Get("a")
	if ok {
		t.Fatal("expected cache miss on empty cache")
	}

	// Set and hit.
	c.Set("a", 42)
	v, ok := c.Get("a")
	if !ok {
		t.Fatal("expected cache hit after Set")
	}
	if v != 42 {
		t.Fatalf("got %d, want 42", v)
	}

	// Overwrite.
	c.Set("a", 99)
	v, ok = c.Get("a")
	if !ok || v != 99 {
		t.Fatalf("got (%d, %v), want (99, true)", v, ok)
	}
}

func TestTTLCache_Expiry(t *testing.T) {
	c := newTTLCache[string, int](10 * time.Millisecond)

	c.Set("a", 1)
	v, ok := c.Get("a")
	if !ok || v != 1 {
		t.Fatalf("expected hit immediately after set, got (%d, %v)", v, ok)
	}

	time.Sleep(20 * time.Millisecond)

	_, ok = c.Get("a")
	if ok {
		t.Fatal("expected cache miss after TTL expiry")
	}
}

func TestTTLCache_NilReceiver(t *testing.T) {
	var c *ttlCache[string, int]

	// Get on nil is a safe no-op.
	_, ok := c.Get("anything")
	if ok {
		t.Fatal("expected miss on nil cache")
	}

	// Set on nil is a safe no-op (should not panic).
	c.Set("anything", 42)

	if c.Len() != 0 {
		t.Fatal("expected 0 length on nil cache")
	}
}

func TestTTLCache_Len(t *testing.T) {
	c := newTTLCache[int, string](time.Hour)

	if c.Len() != 0 {
		t.Fatalf("expected 0, got %d", c.Len())
	}

	c.Set(1, "a")
	c.Set(2, "b")
	if c.Len() != 2 {
		t.Fatalf("expected 2, got %d", c.Len())
	}
}
