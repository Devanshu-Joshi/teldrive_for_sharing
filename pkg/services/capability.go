package services

import (
	"context"

	"github.com/tgdrive/teldrive/internal/crypt"
	"github.com/tgdrive/teldrive/pkg/models"
)

// SharedCapability represents the runtime capability state for a user in shared mode.
// This is the SINGLE source of truth for all shared-mode authorization decisions.
type SharedCapability struct {
	Role      string `json:"role"`                // "host", "approved", "pending", "none"
	Valid     bool   `json:"valid"`               // Whether shared capabilities are active
	Reason    string `json:"reason,omitempty"`     // Reason for invalid capability
	ChannelID *int64 `json:"channelId,omitempty"`  // Host's locked channel ID
}

// ValidateSharedCapability is the centralized runtime capability engine.
// It determines a user's shared-mode role and whether their capabilities are active.
//
// Validation matrix:
//   - host:     validates config groupSecret + encryptionKey against DB stored hash
//   - approved: validates config groupSecret + encryptionKey against host's stored hash
//   - pending:  no validation needed, capabilities limited by role
//   - none:     no validation needed, standalone user
//
// This function is called by: session endpoint, upload routing, file creation,
// group dashboard, and mutation guards.
func (a *apiService) ValidateSharedCapability(ctx context.Context, userId int64) *SharedCapability {
	if !a.cnf.Shared.IsShared {
		return &SharedCapability{Role: "none", Valid: true}
	}

	// Requirement 6: Split-brain hard cleanup during runtime
	var hostCount int64
	a.db.Model(&models.GroupMember{}).Where("status = 'host'").Count(&hostCount)
	if hostCount > 1 {
		a.db.Exec("TRUNCATE TABLE teldrive.group_members CASCADE")
		return &SharedCapability{Role: "none", Valid: true}
	}

	// Query the user's membership row
	var member models.GroupMember
	err := a.db.Where("member_id = ?", userId).First(&member).Error
	if err != nil {
		// No membership row → standalone user in shared-mode instance
		return &SharedCapability{Role: "none", Valid: true}
	}

	switch member.Status {
	case "pending":
		// Pending users get no shared capabilities, but no validation needed
		return &SharedCapability{Role: "pending", Valid: true}

	case "host", "approved":
		// Host and approved members require runtime secret validation
		return a.validateMemberCapability(ctx, &member)

	default:
		return &SharedCapability{Role: "none", Valid: true}
	}
}

// validateMemberCapability performs cryptographic validation for host/approved members.
// Chain: encryptionKey → SHA256 → fingerprint → SHA256(fingerprint + groupSecret) → doubleHash
// The doubleHash must match the stored hash in the host's DB row.
func (a *apiService) validateMemberCapability(ctx context.Context, member *models.GroupMember) *SharedCapability {
	// Step 1: Check if groupSecret is configured
	if a.cnf.Shared.GroupSecret == "" {
		return &SharedCapability{
			Role:      member.Status,
			Valid:     false,
			Reason:    "Shared workspace unavailable: secret or encryption key is invalid.",
			ChannelID: member.ChannelID,
		}
	}

	// Step 2: Resolve the host row (for approved members, we need the host's stored hash)
	var hostMember models.GroupMember
	if member.Status == "host" {
		hostMember = *member
	} else {
		if err := a.db.Where("member_id = ? AND status = 'host'", member.HostID).First(&hostMember).Error; err != nil {
			return &SharedCapability{
				Role:   member.Status,
				Valid:  false,
				Reason: "Host record not found. The group may have been dismantled.",
			}
		}
	}

	// Step 3: Validate the cryptographic chain
	if hostMember.StoredHash == nil {
		return &SharedCapability{
			Role:      member.Status,
			Valid:     false,
			Reason:    "Shared workspace unavailable: secret or encryption key is invalid.",
			ChannelID: hostMember.ChannelID,
		}
	}

	fingerprint := crypt.GetCryptoFingerprint(a.cnf.TG.Uploads.EncryptionKey)
	expectedHash := crypt.ComputeGroupHash(fingerprint, a.cnf.Shared.GroupSecret)

	if *hostMember.StoredHash != expectedHash {
		return &SharedCapability{
			Role:      member.Status,
			Valid:     false,
			Reason:    "Shared workspace unavailable: secret or encryption key is invalid.",
			ChannelID: hostMember.ChannelID,
		}
	}

	// Validation passed — full shared capabilities active
	return &SharedCapability{
		Role:      member.Status,
		Valid:     true,
		ChannelID: hostMember.ChannelID,
	}
}

// isActiveHost checks if the user has an active host row in group_members.
// Uses DB as authoritative source, NOT config. Prevents topology bypass via config toggling.
func (a *apiService) isActiveHost(userId int64) bool {
	var count int64
	a.db.Model(&models.GroupMember{}).Where("member_id = ? AND status = 'host'", userId).Count(&count)
	return count > 0
}

// isHostChannelLocked checks if the specified channel is the active host's locked topology channel.
// Uses DB as authoritative source.
func (a *apiService) isHostChannelLocked(userId int64, channelId int64) bool {
	var hostMember models.GroupMember
	if err := a.db.Where("member_id = ? AND status = 'host'", userId).First(&hostMember).Error; err != nil {
		return false
	}
	return hostMember.ChannelID != nil && *hostMember.ChannelID == channelId
}
