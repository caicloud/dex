package haier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/dex/connector"
	"golang.org/x/oauth2"
)

const (
	apiURL = "https://passport.c.haier.net"
)

type Config struct {
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	RedirectURI  string `json:"redirectURI"`
	URL          string `json:"url"`
}

func (c *Config) Open(logger logrus.FieldLogger) (connector.Connector, error) {
	hc := haierConnector{
		redirectURI:  c.RedirectURI,
		clientID:     c.ClientID,
		clientSecret: c.ClientSecret,
		logger:       logger,
	}
	if c.URL == "" {
		hc.url = apiURL
	}
	return &hc, nil
}

type connectorData struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

var (
	_ connector.CallbackConnector = &haierConnector{}
	_ connector.RefreshConnector  = &haierConnector{}
)

type haierConnector struct {
	redirectURI  string
	clientID     string
	clientSecret string
	url          string
	logger       logrus.FieldLogger
}

func (hc *haierConnector) oauth2Config(scopes connector.Scopes) *Oauth2Config {

	endpoint := oauth2.Endpoint{
		AuthURL:  hc.url + "/oauth2/authorize",
		TokenURL: hc.url + "/oauth2/accessToken",
	}
	return &Oauth2Config{
		Config: &oauth2.Config{
			ClientID:     hc.clientID,
			ClientSecret: hc.clientSecret,
			Endpoint:     endpoint,
			RedirectURL:  hc.redirectURI,
		},
		RefreshTokenURL: hc.url + "/oauth2/refreshToken",
	}
}

func (hc *haierConnector) LoginURL(scopes connector.Scopes, callbackURL, state string) (string, error) {
	if hc.redirectURI != callbackURL {
		return "", fmt.Errorf("expected callback URL %v did not match the URL in the config %v", callbackURL, hc.redirectURI)
	}
	return hc.oauth2Config(scopes).Config.AuthCodeURL(state), nil
}

type oauth2Error struct {
	error            string
	errorDescription string
}

func (e *oauth2Error) Error() string {
	if e.errorDescription == "" {
		return e.error
	}
	return e.error + ": " + e.errorDescription
}

func (hc *haierConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		return identity, &oauth2Error{errType, q.Get("error_description")}
	}

	oauth2Config := hc.oauth2Config(s)

	ctx := r.Context()

	token, err := oauth2Config.Exchange(ctx, q.Get("code"))
	if err != nil {
		return identity, fmt.Errorf("haier: failed to get token: %v", err)
	}
	hc.logger.Infof("token: %v", token)

	client := oauth2Config.Client(ctx, token)

	user, err := hc.user(ctx, client)
	if err != nil {
		return identity, fmt.Errorf("haier: get user: %v", err)
	}

	userDetail := user.Detail
	identity = connector.Identity{
		UserID:        userDetail.Username,
		Username:      userDetail.Nickname,
		Email:         userDetail.Email,
		EmailVerified: true,
	}

	data := connectorData{AccessToken: token.AccessToken, RefreshToken: token.RefreshToken}
	connData, err := json.Marshal(data)
	if err != nil {
		return identity, fmt.Errorf("marshal connector data: %v", err)
	}
	identity.ConnectorData = connData

	return identity, nil
}

func (hc *haierConnector) Refresh(ctx context.Context, s connector.Scopes, ident connector.Identity) (connector.Identity, error) {
	if len(ident.ConnectorData) == 0 {
		return ident, errors.New("no upstream access token found")
	}

	var data connectorData
	if err := json.Unmarshal(ident.ConnectorData, &data); err != nil {
		return ident, fmt.Errorf("haier: unmarshal access token: %v", err)
	}

	client := hc.oauth2Config(s).Client(ctx, &oauth2.Token{AccessToken: data.AccessToken, RefreshToken: data.RefreshToken})
	user, err := hc.user(ctx, client)
	if err != nil {
		return ident, fmt.Errorf("haier: get user: %v", err)
	}

	userDetail := user.Detail
	ident = connector.Identity{
		UserID:        userDetail.Username,
		Username:      userDetail.Nickname,
		Email:         userDetail.Email,
		EmailVerified: true,
	}

	return ident, nil
}

type User struct {
	Code   int        `json:"statuscode"`
	Detail UserDetail `json:"userDetailInfo"`
}

type UserDetail struct {
	Username    string `json:"username"`
	Phone       string `json:"phonenumber"`
	mobilePhone string `json:"mobilephone"`
	Nickname    string `json:"nickname"`
	Email       string `json:"email"`
}

func (hc *haierConnector) user(ctx context.Context, client *http.Client) (*User, error) {
	var u User
	req, err := http.NewRequest("GET", hc.url+"/oauth2/userDetailInfo", nil)
	if err != nil {
		return nil, fmt.Errorf("haier: new req: %v", err)
	}
	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("haier: get URL %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("haier: read body: %v", err)
		}
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	} else if u.Code != 0 {
		return nil, fmt.Errorf("failed to get user info detail, statuscode is %v", u.Code)
	}
	return &u, nil
}
