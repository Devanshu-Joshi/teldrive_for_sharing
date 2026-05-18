package services

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/tgdrive/teldrive/internal/auth"
	"github.com/tgdrive/teldrive/internal/crypt"
	"github.com/tgdrive/teldrive/internal/tgc"
	"github.com/tgdrive/teldrive/internal/utils"
	"github.com/tgdrive/teldrive/pkg/models"
	"gorm.io/gorm"
)

// authenticateUser verifies user credentials and returns the context, user ID, and claims.
func (e *extendedService) authenticateUser(w http.ResponseWriter, r *http.Request) (context.Context, int64, error) {
	var token string
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	} else if strings.HasPrefix(authHeader, "Bearer  ") {
		token = strings.TrimPrefix(authHeader, "Bearer  ")
	} else if authHeader != "" {
		token = authHeader
	}

	if token == "" {
		cookie, err := r.Cookie(authCookieName)
		if err == nil {
			token = cookie.Value
		}
	}

	if token == "" {
		return nil, 0, fmt.Errorf("missing authentication token")
	}

	claims, err := auth.VerifyUser(r.Context(), e.api.db, e.api.cache, e.api.cnf.JWT.Secret, token)
	if err != nil {
		return nil, 0, err
	}
	userId, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil {
		return nil, 0, err
	}
	ctx := auth.WithUser(r.Context(), claims)
	return ctx, userId, nil
}

// verifyChannelAccess checks if the user's personal Telegram session has access to the channel ID.
func (e *extendedService) verifyChannelAccess(ctx context.Context, channelId int64) bool {
	claims := auth.GetJWTUser(ctx)
	if claims == nil || claims.TgSession == "" {
		return false
	}
	client, err := tgc.AuthClient(ctx, &e.api.cnf.TG, claims.TgSession, e.api.newMiddlewares(ctx, 5)...)
	if err != nil {
		return false
	}
	err = tgc.RunWithAuth(ctx, client, "", func(ctx context.Context) error {
		_, err := tgc.GetChannelById(ctx, client.API(), channelId)
		return err
	})
	return err == nil
}

// HandleGroupRoute intercepts and routes group management API requests.
func (e *extendedService) HandleGroupRoute(w http.ResponseWriter, r *http.Request) {
	// Guard: check that shared mode is configured as active in this instance
	if !e.api.cnf.Shared.IsShared {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": "Group sharing is disabled on this instance"}`))
		return
	}

	ctx, userId, err := e.authenticateUser(w, r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "Unauthorized: ` + err.Error() + `"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodPost && r.URL.Path == "/api/group/claim" {
		e.ClaimHost(w, r, ctx, userId)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/group/request" {
		e.RequestAccess(w, r, ctx, userId)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/group/manage" {
		e.ManageGuest(w, r, ctx, userId)
		return
	}
	if r.Method == http.MethodDelete && r.URL.Path == "/api/group/leave" {
		e.LeaveGroup(w, r, ctx, userId)
		return
	}

	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(`{"error": "Not Found"}`))
}

type ClaimRequest struct {
	ChannelID   int64  `json:"channel_id"`
	Fingerprint string `json:"fingerprint"`
}

// ClaimHost handles POST /api/group/claim - Claims the Host role transactionally.
func (e *extendedService) ClaimHost(w http.ResponseWriter, r *http.Request, ctx context.Context, userId int64) {
	var req ClaimRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "Invalid JSON payload"}`))
		return
	}

	if req.ChannelID == 0 || req.Fingerprint == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "channel_id and fingerprint are required"}`))
		return
	}

	// Verify Telegram Channel Access using the user's client session
	if !e.verifyChannelAccess(ctx, req.ChannelID) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": "You do not have access to this Telegram Channel or session is invalid"}`))
		return
	}

	// Generate the out-of-band group secret
	groupSecret := utils.GenerateRandomSecret(32)

	// Explicit database transaction to prevent concurrent claims or partial writes
	err := e.api.db.Transaction(func(tx *gorm.DB) error {
		var count int64
		// Enforce Host Exclusivity inside the transaction
		if err := tx.Model(&models.GroupMember{}).Where("status = 'host'").Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			return fmt.Errorf("host already exists")
		}

		doubleHash := crypt.ComputeGroupHash(req.Fingerprint, groupSecret)

		newHost := &models.GroupMember{
			HostID:     userId,
			MemberID:   userId,
			Status:     "host",
			StoredHash: &doubleHash,
			ChannelID:  &req.ChannelID,
		}

		return tx.Create(newHost).Error
	})

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "` + err.Error() + `"}`))
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status":      "Success",
		"groupSecret": groupSecret,
	})
}

// RequestAccess handles POST /api/group/request - placeholder for next phase
func (e *extendedService) RequestAccess(w http.ResponseWriter, r *http.Request, ctx context.Context, userId int64) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error": "Not implemented in this phase"}`))
}

// ManageGuest handles POST /api/group/manage - placeholder for next phase
func (e *extendedService) ManageGuest(w http.ResponseWriter, r *http.Request, ctx context.Context, userId int64) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error": "Not implemented in this phase"}`))
}

// LeaveGroup handles DELETE /api/group/leave - placeholder for next phase
func (e *extendedService) LeaveGroup(w http.ResponseWriter, r *http.Request, ctx context.Context, userId int64) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error": "Not implemented in this phase"}`))
}
