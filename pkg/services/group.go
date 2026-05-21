package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tgdrive/teldrive/internal/api"
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

// getReadableChannelTitle verifies the user can READ the channel and returns its title.
// IMPORTANT: This must NOT require admin/write permissions (readonly channels are allowed).
func (e *extendedService) getReadableChannelTitle(ctx context.Context, channelId int64) (string, error) {
	claims := auth.GetJWTUser(ctx)
	if claims == nil || claims.TgSession == "" {
		return "", fmt.Errorf("missing telegram session")
	}
	client, err := tgc.AuthClient(ctx, &e.api.cnf.TG, claims.TgSession, e.api.newMiddlewares(ctx, 5)...)
	if err != nil {
		return "", err
	}

	var title string
	err = tgc.RunWithAuth(ctx, client, "", func(ctx context.Context) error {
		ch, err := tgc.GetChannelFull(ctx, client.API(), channelId)
		if err != nil {
			return err
		}
		title = ch.Title
		return nil
	})
	if err != nil {
		return "", err
	}
	if title == "" {
		title = "Unknown Channel"
	}
	return title, nil
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
	if r.Method == http.MethodGet && r.URL.Path == "/api/group/channel-info" {
		e.GetChannelInfo(w, r, ctx, userId)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/group/status" {
		e.GetGroupStatus(w, r, ctx, userId)
		return
	}

	if r.Method == http.MethodGet && r.URL.Path == "/api/group/pending" {
		e.GetPendingMembers(w, r, ctx, userId)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/group/members" {
		e.GetApprovedMembers(w, r, ctx, userId)
		return
	}

	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(`{"error": "Not Found"}`))
}

func (e *extendedService) GetChannelInfo(w http.ResponseWriter, r *http.Request, ctx context.Context, userId int64) {
	channelId, err := e.api.channelManager.CurrentChannel(ctx, userId)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		if errors.Is(err, tgc.ErrNoDefaultChannel) {
			w.Write([]byte(`{"error": "No default storage channel configured."}`))
			return
		}
		w.Write([]byte(`{"error": "` + err.Error() + `"}`))
		return
	}

	channelName, tgErr := e.getReadableChannelTitle(ctx, channelId)
	if tgErr != nil {
		// Fallback to DB if Telegram lookup fails.
		var channel models.Channel
		if err := e.api.db.Where("channel_id = ?", channelId).First(&channel).Error; err == nil && channel.ChannelName != "" {
			channelName = channel.ChannelName
		} else {
			channelName = "Unknown Channel"
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"channelId":   channelId,
		"channelName": channelName,
	})
}

func (e *extendedService) GetGroupStatus(w http.ResponseWriter, r *http.Request, ctx context.Context, userId int64) {
	cap := e.api.ValidateSharedCapability(ctx, userId)

	var hostCount int64
	e.api.db.Model(&models.GroupMember{}).Where("status = 'host'").Count(&hostCount)
	hostExists := hostCount > 0

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"role":            cap.Role,
		"hostExists":      hostExists,
		"channelLocked":   hostExists, // If host exists, their channel is locked
		"capabilityValid": cap.Valid,
	})
}

// ClaimHost handles POST /api/group/claim - Claims the Host role transactionally.
func (e *extendedService) ClaimHost(w http.ResponseWriter, r *http.Request, ctx context.Context, userId int64) {
	// Auto-fetch current default channel
	channelId, err := e.api.channelManager.CurrentChannel(ctx, userId)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		if errors.Is(err, tgc.ErrNoDefaultChannel) {
			w.Write([]byte(`{"error": "No default storage channel configured."}`))
			return
		}
		w.Write([]byte(`{"error": "` + err.Error() + `"}`))
		return
	}

	// Read-only access validation + authoritative channel name fetch
	channelName, err := e.getReadableChannelTitle(ctx, channelId)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": "You do not have access to this Telegram Channel or session is invalid"}`))
		return
	}

	// Auto-compute fingerprint from encryption key
	fingerprint := crypt.GetCryptoFingerprint(e.api.cnf.TG.Uploads.EncryptionKey)

	// Generate the out-of-band group secret
	groupSecret := utils.GenerateRandomSecret(32)

	// Explicit database transaction to prevent concurrent claims or partial writes
	err = e.api.db.Transaction(func(tx *gorm.DB) error {
		var count int64
		// Enforce Host Exclusivity inside the transaction
		if err := tx.Model(&models.GroupMember{}).Where("status = 'host'").Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			return newHttpError(http.StatusConflict, "host already exists")
		}

		doubleHash := crypt.ComputeGroupHash(fingerprint, groupSecret)

		newHost := &models.GroupMember{
			HostID:      userId,
			MemberID:    userId,
			Status:      "host",
			StoredHash:  &doubleHash,
			ChannelID:   &channelId,
			ChannelName: &channelName,
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
		"channelId":   channelId,
		"channelName": channelName,
	})
}

// RequestAccess handles POST /api/group/request - Guest requests access to join the group.
func (e *extendedService) RequestAccess(w http.ResponseWriter, r *http.Request, ctx context.Context, userId int64) {
	groupSecret := e.api.cnf.Shared.GroupSecret
	if groupSecret == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "No shared workspace secret configured."}`))
		return
	}

	// Transaction to safely fetch, validate and insert access request
	err := e.api.db.Transaction(func(tx *gorm.DB) error {
		// 1. Fetch active host record. There MUST be exactly one host.
		var count int64
		if err := tx.Model(&models.GroupMember{}).Where("status = 'host'").Count(&count).Error; err != nil {
			return err
		}
		if count > 1 {
			tx.Exec("TRUNCATE TABLE teldrive.group_members CASCADE")
			return newHttpError(http.StatusNotFound, "group topology invalid or dismantled")
		} else if count == 0 {
			return newHttpError(http.StatusNotFound, "group topology invalid or dismantled")
		}

		var host models.GroupMember
		if err := tx.Where("status = 'host'").First(&host).Error; err != nil {
			return err
		}

		// 2. Reject self-request (Host requesting access to themselves is redundant/invalid)
		if host.MemberID == userId {
			return newHttpError(http.StatusConflict, "you are already the active host of this group")
		}

		// 3. Reject duplicate pending or approved requests
		count = 0
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
		if _, err := e.getReadableChannelTitle(ctx, *host.ChannelID); err != nil {
			return newHttpError(http.StatusForbidden, "Cannot join shared workspace because host channel is not accessible.")
		}

		// 5. Verify cryptographic compatibility safely
		if host.StoredHash == nil {
			return newHttpError(http.StatusBadRequest, "host has no cryptographic fingerprint stored")
		}

		fingerprint := crypt.GetCryptoFingerprint(e.api.cnf.TG.Uploads.EncryptionKey)
		calculatedDoubleHash := crypt.ComputeGroupHash(fingerprint, groupSecret)
		if *host.StoredHash != calculatedDoubleHash {
			return newHttpError(http.StatusForbidden, "Shared workspace unavailable: secret or encryption key is invalid.")
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

	if req.Action != "approve" && req.Action != "reject" && req.Action != "remove" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "Invalid action. Must be 'approve', 'reject', or 'remove'"}`))
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

		if member.Status != "pending" && (req.Action == "approve" || req.Action == "reject") {
			return newHttpError(http.StatusConflict, fmt.Sprintf("member is already in '%s' status", member.Status))
		}
		if member.Status != "approved" && req.Action == "remove" {
			return newHttpError(http.StatusConflict, fmt.Sprintf("cannot remove member in '%s' status", member.Status))
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
		} else if req.Action == "remove" {
			// Perform removal (row deletion)
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

// BuildVirtualRoot builds a mock synthetic folder structure for a given host user.
// It is a purely additive helper with no persistence or side effects.
func BuildVirtualRoot(db *gorm.DB, hostID int64) (api.File, error) {
	name := fmt.Sprintf("Shared Space (%d)", hostID)
	var hostUser models.User
	if err := db.Where("user_id = ?", hostID).First(&hostUser).Error; err == nil {
		if hostUser.UserName != "" {
			name = "@" + hostUser.UserName
		} else if hostUser.Name != "" {
			name = hostUser.Name
		}
	}

	virtualFile := api.File{
		ID:        api.NewOptString(fmt.Sprintf("virtual_%d", hostID)),
		Name:      name,
		Type:      api.FileTypeFolder,
		MimeType:  api.NewOptString("drive/folder"),
		Size:      api.NewOptInt64(0),
		ParentId:  api.NewOptString("root"),
		UpdatedAt: api.NewOptDateTime(time.Now().UTC()),
	}

	return virtualFile, nil
}

type MemberResponse struct {
	UserId   int64  `json:"userId"`
	Username string `json:"username"`
	Status   string `json:"status"`
}

func (e *extendedService) getMembersByStatus(w http.ResponseWriter, r *http.Request, ctx context.Context, userId int64, status string) {
	// Only host can view members
	var host models.GroupMember
	if err := e.api.db.Where("status = 'host' AND member_id = ?", userId).First(&host).Error; err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": "unauthorized: caller is not the active host"}`))
		return
	}

	var members []models.GroupMember
	if err := e.api.db.Where("status = ?", status).Find(&members).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "failed to fetch members"}`))
		return
	}

	var response []MemberResponse
	for _, m := range members {
		// skip the host themselves in the members list
		if m.MemberID == host.HostID {
			continue
		}
		var user models.User
		username := fmt.Sprintf("User %d", m.MemberID)
		if err := e.api.db.Where("user_id = ?", m.MemberID).First(&user).Error; err == nil {
			if user.UserName != "" {
				username = "@" + user.UserName
			} else if user.Name != "" {
				username = user.Name
			}
		}
		response = append(response, MemberResponse{
			UserId:   m.MemberID,
			Username: username,
			Status:   m.Status,
		})
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func (e *extendedService) GetPendingMembers(w http.ResponseWriter, r *http.Request, ctx context.Context, userId int64) {
	e.getMembersByStatus(w, r, ctx, userId, "pending")
}

func (e *extendedService) GetApprovedMembers(w http.ResponseWriter, r *http.Request, ctx context.Context, userId int64) {
	e.getMembersByStatus(w, r, ctx, userId, "approved")
}
