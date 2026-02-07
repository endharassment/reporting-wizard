-- Cache of recursive BGP upstream relationships.
-- Populated during infra discovery by walking the upstream chain until
-- Tier 1 (no upstreams) or a cycle is detected.
CREATE TABLE IF NOT EXISTS upstream_cache (
    asn           INTEGER NOT NULL,
    upstream_asn  INTEGER NOT NULL,
    fetched_at    TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (asn, upstream_asn)
);
CREATE INDEX IF NOT EXISTS idx_upstream_cache_asn ON upstream_cache(asn);
