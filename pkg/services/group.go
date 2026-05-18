package services

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
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
	"gorm.io/gorm/clause"
)

type httpError struct {
	Code int
	Msg  string
}

func (e *httpError) Error() string {
	return e.Msg
}

func newHttpError(code int, msg string) *httpError {
	return &httpError{Code: code, Msg: msg}
}

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
			return newHttpError(http.StatusConflict, "host already exists")
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
		var hErr *httpError
		if errors.As(err, &hErr) {
			w.WriteHeader(hErr.Code)
			w.Write([]byte(`{"error": "` + hErr.Msg + `"}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "` + err.Error() + `"}`))
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status":      "Success",
		"groupSecret": groupSecret,
	})
}

type JoinRequest struct {
	Fingerprint string `json:"fingerprint"`
}

// RequestAccess handles POST /api/group/request - Guest requests access to join the group.
func (e *extendedService) RequestAccess(w http.ResponseWriter, r *http.Request, ctx context.Context, userId int64) {
	var req JoinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "Invalid JSON payload"}`))
		return
	}

	if req.Fingerprint == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "fingerprint is required"}`))
		return
	}

	if e.api.cnf.Shared.GroupSecret == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "Group secret is not configured in local config.toml"}`))
		return
	}

	// Transaction to safely fetch, validate and insert access request
	err := e.api.db.Transaction(func(tx *gorm.DB) error {
		// 1. Fetch active host record
		var host models.GroupMember
		if err := tx.Where("status = 'host'").First(&host).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return newHttpError(http.StatusNotFound, "no active host found in the database")
			}
			return err
		}

		// 2. Reject self-request (Host requesting access to themselves is redundant/invalid)
		if host.MemberID == userId {
			return newHttpError(http.StatusConflict, "you are already the active host of this group")
		}

		// 3. Reject duplicate pending or approved requests
		var count int64
		if err := tx.Model(&models.GroupMember{}).Where("member_id = ?", userId).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			return newHttpError(http.StatusConflict, "request already pending or user is already a member")
		}

		// 4. Verify basic Telegram Channel Access using the Guest's session
		if host.ChannelID == nil {
			return newHttpError(http.StatusBadRequest, "host's Telegram channel is invalid/missing")
		}
		if !e.verifyChannelAccess(ctx, *host.ChannelID) {
			return newHttpError(http.StatusForbidden, "you do not have access to the Host's required Telegram Channel")
		}

		// 5. Verify cryptographic compatibility safely
		if host.StoredHash == nil {
			return newHttpError(http.StatusBadRequest, "host has no cryptographic fingerprint stored")
		}
		calculatedDoubleHash := crypt.ComputeGroupHash(req.Fingerprint, e.api.cnf.Shared.GroupSecret)
		if *host.StoredHash != calculatedDoubleHash {
			return newHttpError(http.StatusForbidden, "encryption key or group secret mismatch")
		}

		// 6. Create the pending request record
		newPending := &models.GroupMember{
			HostID:   host.MemberID,
			MemberID: userId,
			Status:   "pending",
		}
		return tx.Create(newPending).Error
	})

	if err != nil {
		var hErr *httpError
		if errors.As(err, &hErr) {
			w.WriteHeader(hErr.Code)
			w.Write([]byte(`{"error": "` + hErr.Msg + `"}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "` + err.Error() + `"}`))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "Success", "message": "Join request submitted successfully. Awaiting Host approval."}`))
}

type ManageRequest struct {
	MemberID int64  `json:"member_id"`
	Action   string `json:"action"`
}

// ManageGuest handles POST /api/group/manage - Host approves or rejects a pending guest.
func (e *extendedService) ManageGuest(w http.ResponseWriter, r *http.Request, ctx context.Context, userId int64) {
	var req ManageRequest
	
	// Support JSON parsing
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Fallback to parsing from PostForm values if JSON decoding fails
		r.ParseForm()
		memberIdStr := r.FormValue("member_id")
		actionStr := r.FormValue("action")
		if memberIdStr == "" || actionStr == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "Invalid request payload. member_id and action are required."}`))
			return
		}
		parsedMemberId, err := strconv.ParseInt(memberIdStr, 10, 64)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "Invalid member_id format"}`))
			return
		}
		req.MemberID = parsedMemberId
		req.Action = actionStr
	}

	if req.MemberID == 0 || req.Action == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "member_id and action are required"}`))
		return
	}

	if req.Action != "approve" && req.Action != "reject" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "Invalid action. Must be 'approve' or 'reject'"}`))
		return
	}

	if req.MemberID == userId {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "You cannot manage your own host membership"}`))
		return
	}

	// Database transaction to prevent approval race conditions and enforce atomic updates
	err := e.api.db.Transaction(func(tx *gorm.DB) error {
		// 1. Verify caller is the active Host and lock Host's row to serialize all member management
		var host models.GroupMember
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("status = 'host' AND member_id = ?", userId).First(&host).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return newHttpError(http.StatusForbidden, "unauthorized: caller is not the active host")
			}
			return err
		}

		// 2. Fetch the target member record
		var member models.GroupMember
		if err := tx.Where("member_id = ?", req.MemberID).First(&member).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return newHttpError(http.StatusNotFound, "pending request not found")
			}
			return err
		}

		if member.Status != "pending" {
			return newHttpError(http.StatusConflict, fmt.Sprintf("member is already in '%s' status", member.Status))
		}

		if req.Action == "approve" {
			// Enforce 50-member hard capacity limit inside the transaction
			var activeCount int64
			if err := tx.Model(&models.GroupMember{}).Where("status IN ('host', 'approved')").Count(&activeCount).Error; err != nil {
				return err
			}
			if activeCount >= 50 {
				return newHttpError(http.StatusConflict, "group capacity reached (max 50 members)")
			}

			// Perform approval
			if err := tx.Model(&models.GroupMember{}).Where("member_id = ?", req.MemberID).Update("status", "approved").Error; err != nil {
				return err
			}
		} else if req.Action == "reject" {
			// Perform rejection (row deletion)
			if err := tx.Where("member_id = ?", req.MemberID).Delete(&models.GroupMember{}).Error; err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		var hErr *httpError
		if errors.As(err, &hErr) {
			w.WriteHeader(hErr.Code)
			w.Write([]byte(`{"error": "` + hErr.Msg + `"}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "` + err.Error() + `"}`))
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status":  "Success",
		"message": fmt.Sprintf("Guest was successfully %sd", req.Action),
	})
}

// LeaveGroup handles DELETE /api/group/leave - Guest leaves or Host resigns the group.
func (e *extendedService) LeaveGroup(w http.ResponseWriter, r *http.Request, ctx context.Context, userId int64) {
	// Execute the entire flow inside an explicit database transaction
	err := e.api.db.Transaction(func(tx *gorm.DB) error {
		// 1. Fetch the caller's membership status with a write lock to prevent concurrency races
		var callerMember models.GroupMember
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("member_id = ?", userId).First(&callerMember).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return newHttpError(http.StatusNotFound, "you are not a member of any group")
			}
			return err
		}

		// 2. Branch based on status: Host Resignation vs Guest Leave
		if callerMember.Status == "host" {
			// Host Resignation Flow
			// Wipes out the ENTIRE group membership table to completely dismantle the group.
			// We use DELETE instead of TRUNCATE for superior transactional safety, GORM lifecycle compatibility,
			// and to avoid table-level lockups caused by ACCESS EXCLUSIVE locks.
			if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&models.GroupMember{}).Error; err != nil {
				return err
			}
		} else {
			// Guest Leave Flow (Approved or Pending guests)
			// Delete ONLY the caller's membership row
			if err := tx.Where("member_id = ?", userId).Delete(&models.GroupMember{}).Error; err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		var hErr *httpError
		if errors.As(err, &hErr) {
			w.WriteHeader(hErr.Code)
			w.Write([]byte(`{"error": "` + hErr.Msg + `"}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "` + err.Error() + `"}`))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "Success", "message": "Successfully left the group or dismantled it"}`))
}
