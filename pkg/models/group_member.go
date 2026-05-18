package models

import "time"

// GroupMember represents the state machine for collaborative networking in TelDrive.
type GroupMember struct {
	ID         uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	HostID     int64     `gorm:"type:bigint;not null;index" json:"host_id"`
	MemberID   int64     `gorm:"type:bigint;not null;uniqueIndex" json:"member_id"`
	Status     string    `gorm:"type:varchar(50);not null" json:"status"`
	
	// Configuration Data (Pointers allow NULL values for Guest rows)
	StoredHash *string   `gorm:"type:varchar(64)" json:"stored_hash,omitempty"` 
	ChannelID  *int64    `gorm:"type:bigint" json:"channel_id,omitempty"` 
	
	CreatedAt  time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt  time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}
