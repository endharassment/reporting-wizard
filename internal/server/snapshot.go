package server

import (
	"context"
	"log"
	"time"

	"github.com/endharassment/reporting-wizard/internal/model"
	"github.com/google/uuid"
)

// snapshotURLs performs best-effort text-only snapshots of the given URLs
// and stores the results in the database. This runs asynchronously so the
// user doesn't wait for potentially slow Tor fetches.
func (s *Server) snapshotURLs(reportID string, urls []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	for _, u := range urls {
		now := time.Now().UTC()
		snap := &model.URLSnapshot{
			ID:        uuid.New().String(),
			ReportID:  reportID,
			URL:       u,
			FetchedAt: now,
			CreatedAt: now,
		}

		text, err := s.snapshotter.Snapshot(ctx, u)
		if err != nil {
			log.Printf("WARN: snapshot %s: %v", u, err)
			snap.Error = err.Error()
		} else {
			snap.TextContent = text
		}

		if err := s.store.CreateURLSnapshot(ctx, snap); err != nil {
			log.Printf("ERROR: store snapshot for %s: %v", u, err)
		}
	}
}
