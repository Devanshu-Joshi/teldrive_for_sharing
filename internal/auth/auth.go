package auth

import (
	"context"
	"fmt"
	"strconv"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ogen-go/ogen/ogenerrors"
	"github.com/tgdrive/teldrive/internal/api"
	"github.com/tgdrive/teldrive/internal/cache"
	"github.com/tgdrive/teldrive/internal/config"
	"github.com/tgdrive/teldrive/pkg/models"
	"github.com/tgdrive/teldrive/pkg/types"
	"gorm.io/gorm"
)

type authContextKey string

const authKey authContextKey = "authUser"

func Encode(secret string, claims *types.JWTClaims) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(secret))
}

func Decode(secret string, token string) (*types.JWTClaims, error) {
	claims := &types.JWTClaims{}

	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	if !tkn.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, err
}

func GetUser(c context.Context) int64 {
	authUser, ok := c.Value(authKey).(*types.JWTClaims)
	if !ok || authUser == nil {
		return 0
	}
	userId, _ := strconv.ParseInt(authUser.Subject, 10, 64)
	return userId
}

// GetUserGroup retrieves the active group member user IDs (up to 50) and the Host's Channel ID.
func GetUserGroup(c context.Context, db *gorm.DB, isShared bool) ([]int64, int64) {
	userId := GetUser(c)
	if userId == 0 {
		return []int64{0}, 0
	}
	if !isShared {
		return []int64{userId}, 0
	}

	var status string
	var hostId int64

	err := db.Model(&models.GroupMember{}).Select("host_id", "status").Where("member_id = ?", userId).Row().Scan(&hostId, &status)
	if err != nil {
		return []int64{userId}, 0 // Pending or un-affiliated
	}

	var channelId int64
	db.Model(&models.GroupMember{}).Select("channel_id").Where("member_id = ? AND status = 'host'", hostId).Row().Scan(&channelId)

	var groupIds []int64
	if status == "approved" {
		db.Model(&models.GroupMember{}).Where("host_id = ? AND status = 'approved'", hostId).
			Order("created_at ASC").Pluck("member_id", &groupIds)
	} else if status == "host" {
		hostId = userId
		db.Model(&models.GroupMember{}).Where("host_id = ? AND status = 'approved'", userId).
			Order("created_at ASC").Pluck("member_id", &groupIds)
	}

	finalIds := []int64{hostId}
	finalIds = append(finalIds, groupIds...)

	if len(finalIds) > 50 {
		return finalIds[:50], channelId
	}
	return finalIds, channelId
}

func GetJWTUser(c context.Context) *types.JWTClaims {
	authUser, ok := c.Value(authKey).(*types.JWTClaims)
	if !ok {
		return nil
	}
	return authUser
}

func VerifyUser(ctx context.Context, db *gorm.DB, cache cache.Cacher, secret, authCookie string) (*types.JWTClaims, error) {
	claims, err := Decode(secret, authCookie)

	if err != nil {
		return nil, err
	}

	var session *models.Session

	session, err = GetSessionByHash(ctx, db, cache, claims.Hash)

	if err != nil {
		return nil, fmt.Errorf("invalid session")
	}

	claims.TgSession = session.Session

	return claims, nil
}

func GetSessionByHash(ctx context.Context, db *gorm.DB, cache cache.Cacher, hash string) (*models.Session, error) {
	var session models.Session
	key := fmt.Sprintf("sessions:%s", hash)

	err := cache.Get(ctx, key, &session)

	if err != nil {
		if err := db.Model(&models.Session{}).Where("hash = ?", hash).First(&session).Error; err != nil {
			return nil, err
		}
		cache.Set(ctx, key, &session, 0)
	}

	return &session, nil

}

type securityHandler struct {
	db    *gorm.DB
	cache cache.Cacher
	cfg   *config.JWTConfig
}

func (s *securityHandler) HandleApiKeyAuth(ctx context.Context, operationName api.OperationName, t api.ApiKeyAuth) (context.Context, error) {
	return s.handleAuth(ctx, t.APIKey)
}

func (s *securityHandler) HandleBearerAuth(ctx context.Context, operationName api.OperationName, t api.BearerAuth) (context.Context, error) {
	return s.handleAuth(ctx, t.Token)
}

func (s *securityHandler) handleAuth(ctx context.Context, token string) (context.Context, error) {
	claims, err := VerifyUser(ctx, s.db, s.cache, s.cfg.Secret, token)
	if err != nil {
		return nil, &ogenerrors.SecurityError{Err: err}
	}
	return context.WithValue(ctx, authKey, claims), nil
}

func NewSecurityHandler(db *gorm.DB, cache cache.Cacher, cfg *config.JWTConfig) api.SecurityHandler {
	return &securityHandler{db: db, cache: cache, cfg: cfg}
}

var _ api.SecurityHandler = (*securityHandler)(nil)
