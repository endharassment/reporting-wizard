package store

import (
	"context"
	"testing"
	"time"

	"github.com/endharassment/reporting-wizard/internal/model"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dir := t.TempDir()
	s, err := NewSQLiteStore(context.Background(), dir+"/test.db")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	// Seed an admin user for invite creation.
	err = s.CreateUser(context.Background(), &model.User{
		ID:        "admin-1",
		Email:     "admin@example.com",
		Name:      "Admin",
		IsAdmin:   true,
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("seed admin user: %v", err)
	}
	return s
}

func makeInvite(code string) *model.Invite {
	return &model.Invite{
		ID:        "inv-" + code,
		Code:      code,
		CreatedBy: "admin-1",
		MaxUses:   1,
		CreatedAt: time.Now().UTC(),
	}
}

func TestCreateAndGetInvite(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	inv := makeInvite("abc123")
	inv.Email = "user@example.com"

	if err := s.CreateInvite(ctx, inv); err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}

	got, err := s.GetInviteByCode(ctx, "abc123")
	if err != nil {
		t.Fatalf("GetInviteByCode: %v", err)
	}
	if got.ID != inv.ID {
		t.Errorf("ID = %q, want %q", got.ID, inv.ID)
	}
	if got.Email != "user@example.com" {
		t.Errorf("Email = %q, want %q", got.Email, "user@example.com")
	}
	if got.MaxUses != 1 {
		t.Errorf("MaxUses = %d, want 1", got.MaxUses)
	}
	if got.UseCount != 0 {
		t.Errorf("UseCount = %d, want 0", got.UseCount)
	}
	if got.Revoked {
		t.Error("Revoked = true, want false")
	}
}

func TestGetInviteByCode_NotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.GetInviteByCode(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent invite code")
	}
}

func TestRedeemInvite(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(s *SQLiteStore, ctx context.Context)
		code      string
		wantErr   bool
		wantErrIs error
	}{
		{
			name: "valid single-use invite",
			setup: func(s *SQLiteStore, ctx context.Context) {
				s.CreateInvite(ctx, makeInvite("valid1"))
			},
			code: "valid1",
		},
		{
			name: "exhausted single-use invite",
			setup: func(s *SQLiteStore, ctx context.Context) {
				inv := makeInvite("used1")
				inv.UseCount = 1
				s.CreateInvite(ctx, inv)
			},
			code:      "used1",
			wantErr:   true,
			wantErrIs: ErrInviteInvalid,
		},
		{
			name: "revoked invite",
			setup: func(s *SQLiteStore, ctx context.Context) {
				s.CreateInvite(ctx, makeInvite("revoked1"))
				s.RevokeInvite(ctx, "inv-revoked1")
			},
			code:      "revoked1",
			wantErr:   true,
			wantErrIs: ErrInviteInvalid,
		},
		{
			name: "expired invite",
			setup: func(s *SQLiteStore, ctx context.Context) {
				inv := makeInvite("expired1")
				inv.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour)
				s.CreateInvite(ctx, inv)
			},
			code:      "expired1",
			wantErr:   true,
			wantErrIs: ErrInviteInvalid,
		},
		{
			name: "multi-use invite has capacity",
			setup: func(s *SQLiteStore, ctx context.Context) {
				inv := makeInvite("multi1")
				inv.MaxUses = 3
				s.CreateInvite(ctx, inv)
			},
			code: "multi1",
		},
		{
			name: "nonexistent code",
			setup: func(s *SQLiteStore, ctx context.Context) {
				// no invite created
			},
			code:      "doesnotexist",
			wantErr:   true,
			wantErrIs: ErrInviteInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestStore(t)
			ctx := context.Background()

			// Seed a user to be the redeemer.
			s.CreateUser(ctx, &model.User{
				ID:        "user-1",
				Email:     "user1@example.com",
				Name:      "User 1",
				CreatedAt: time.Now().UTC(),
			})

			tt.setup(s, ctx)

			err := s.RedeemInvite(ctx, tt.code, "user-1")
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.wantErrIs != nil && err != tt.wantErrIs {
					t.Errorf("error = %v, want %v", err, tt.wantErrIs)
				}
				return
			}
			if err != nil {
				t.Fatalf("RedeemInvite: %v", err)
			}

			// Verify use_count incremented.
			got, err := s.GetInviteByCode(ctx, tt.code)
			if err != nil {
				t.Fatalf("GetInviteByCode after redeem: %v", err)
			}
			if got.UseCount != 1 {
				t.Errorf("UseCount = %d, want 1", got.UseCount)
			}
			if got.UsedBy != "user-1" {
				t.Errorf("UsedBy = %q, want %q", got.UsedBy, "user-1")
			}
		})
	}
}

func TestRedeemInvite_ExhaustsMultiUse(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	inv := makeInvite("multi2")
	inv.MaxUses = 2
	s.CreateInvite(ctx, inv)

	for i, uid := range []string{"u1", "u2"} {
		s.CreateUser(ctx, &model.User{
			ID: uid, Email: uid + "@example.com", Name: uid,
			CreatedAt: time.Now().UTC(),
		})
		if err := s.RedeemInvite(ctx, "multi2", uid); err != nil {
			t.Fatalf("redeem %d: %v", i+1, err)
		}
	}

	// Third attempt should fail.
	s.CreateUser(ctx, &model.User{
		ID: "u3", Email: "u3@example.com", Name: "u3",
		CreatedAt: time.Now().UTC(),
	})
	if err := s.RedeemInvite(ctx, "multi2", "u3"); err != ErrInviteInvalid {
		t.Errorf("expected ErrInviteInvalid on exhausted multi-use invite, got: %v", err)
	}
}

func TestListInvites(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	s.CreateInvite(ctx, makeInvite("list1"))
	s.CreateInvite(ctx, makeInvite("list2"))

	invites, err := s.ListInvites(ctx)
	if err != nil {
		t.Fatalf("ListInvites: %v", err)
	}
	if len(invites) != 2 {
		t.Errorf("len(invites) = %d, want 2", len(invites))
	}
}

func TestRevokeInvite(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	s.CreateInvite(ctx, makeInvite("rev1"))

	if err := s.RevokeInvite(ctx, "inv-rev1"); err != nil {
		t.Fatalf("RevokeInvite: %v", err)
	}

	got, err := s.GetInviteByCode(ctx, "rev1")
	if err != nil {
		t.Fatalf("GetInviteByCode: %v", err)
	}
	if !got.Revoked {
		t.Error("Revoked = false, want true")
	}

	// Revoked invite cannot be redeemed.
	if err := s.RedeemInvite(ctx, "rev1", "admin-1"); err != ErrInviteInvalid {
		t.Errorf("expected ErrInviteInvalid for revoked invite, got: %v", err)
	}
}
