package google

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// UserInfo represents the user profile from Google
type UserInfo struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
}

// GoogleAuth manages Google OAuth2 flow
type GoogleAuth struct {
	config *oauth2.Config
}

// Option func for functional options pattern
type Option func(*GoogleAuth)

// Structured errors
type ExchangeError struct{ Err error }
type UserInfoError struct {
	StatusCode int
	Body       []byte
	Err        error
}

func (e ExchangeError) Error() string { return fmt.Sprintf("failed to exchange code: %v", e.Err) }
func (e ExchangeError) Unwrap() error { return e.Err }
func (e UserInfoError) Error() string {
	return fmt.Sprintf("failed to get userinfo (status %d): %v", e.StatusCode, e.Err)
}
func (e UserInfoError) Unwrap() error { return e.Err }

// New creates a new GoogleAuth instance with sensible defaults
func NewAuth(clientID, clientSecret, redirectURL string, scopes []string, opts ...Option) *GoogleAuth {
	if len(scopes) == 0 {
		scopes = []string{
			"openid",
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		}
	}

	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Endpoint:     google.Endpoint,
	}

	ga := &GoogleAuth{
		config: config,
	}

	for _, opt := range opts {
		opt(ga)
	}

	return ga
}

// AuthURL generates the Google Authentication URL
func (g *GoogleAuth) AuthURL(state string, opts ...oauth2.AuthCodeOption) string {
	return g.config.AuthCodeURL(state, opts...)
}

// Exchange code for token
func (g *GoogleAuth) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	if code == "" {
		return nil, fmt.Errorf("code is empty")
	}

	token, err := g.config.Exchange(ctx, code)
	if err != nil {
		return nil, ExchangeError{Err: err}
	}
	return token, nil
}

// Client returns an authenticated HTTP client (respects custom timeout/transport)
func (g *GoogleAuth) Client(ctx context.Context, token *oauth2.Token) *http.Client {
	return g.config.Client(ctx, token)
}

// GetUserInfo fetches user profile
func (g *GoogleAuth) GetUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	if token == nil {
		return nil, fmt.Errorf("token is nil")
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", "https://openidconnect.googleapis.com/v1/userinfo", nil)
	client := g.Client(ctx, token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, UserInfoError{Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, UserInfoError{
			StatusCode: resp.StatusCode,
			Body:       body,
			Err:        fmt.Errorf("unexpected status: %s", resp.Status),
		}
	}

	var user UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode userinfo: %w", err)
	}

	return &user, nil
}
