package services

import "context"

const sharedChannelInaccessibleMessage = "Shared storage channel is no longer accessible."

// storageChannelID returns the effective storage channel for the caller.
//
// When shared capability is VALID for host/approved members, the authoritative
// host-selected channel is forced (immutably) as the effective storage channel.
//
// When shared capability is INVALID, the user falls back to their personal
// default channel behavior.
func (a *apiService) storageChannelID(ctx context.Context, userId int64) (int64, error) {
	cap := a.ValidateSharedCapability(ctx, userId)
	if cap.Valid && cap.ChannelID != nil && (cap.Role == "host" || cap.Role == "approved") {
		return *cap.ChannelID, nil
	}
	return a.channelManager.CurrentChannel(ctx, userId)
}
