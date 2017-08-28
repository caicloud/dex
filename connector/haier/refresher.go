package haier

import (
	"context"
	"errors"
	"net/url"

	"golang.org/x/oauth2"
)

type tokenRefresher struct {
	ctx          context.Context // used to get HTTP requests
	conf         *Oauth2Config
	refreshToken string
}

// WARNING: Token is not safe for concurrent access, as it
// updates the tokenRefresher's refreshToken field.
// Within this package, it is used by reuseTokenSource which
// synchronizes calls to this method with its own mutex.
func (tf *tokenRefresher) Token() (*oauth2.Token, error) {
	if tf.refreshToken == "" {
		return nil, errors.New("oauth2: token expired and refresh token is not set")
	}

	tk, err := retrieveToken(tf.ctx, tf.conf, tf.conf.RefreshTokenURL, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tf.refreshToken},
	})

	if err != nil {
		return nil, err
	}
	if tf.refreshToken != tk.RefreshToken {
		tf.refreshToken = tk.RefreshToken
	}
	return tk, err
}
