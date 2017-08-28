package haier

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

type Oauth2Config struct {
	Config *oauth2.Config
	// used for haier refresh request
	RefreshTokenURL string
}

func (c *Oauth2Config) TokenSource(ctx context.Context, t *oauth2.Token) oauth2.TokenSource {
	tkr := &tokenRefresher{
		ctx:  ctx,
		conf: c,
	}
	if t != nil {
		tkr.refreshToken = t.RefreshToken
	}
	return tkr
}

func (c *Oauth2Config) Client(ctx context.Context, t *oauth2.Token) *http.Client {
	return &http.Client{
		Transport: &Transport{
			Base:   http.DefaultTransport,
			Source: oauth2.ReuseTokenSource(t, c.TokenSource(ctx, t)),
		},
	}
}

func (c *Oauth2Config) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return retrieveToken(ctx, c, c.Config.Endpoint.TokenURL, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": CondVal(c.Config.RedirectURL),
		"scope":        CondVal(strings.Join(c.Config.Scopes, " ")),
	})
}

func CondVal(v string) []string {
	if v == "" {
		return nil
	}
	return []string{v}
}
