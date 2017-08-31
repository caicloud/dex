package cauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/Sirupsen/logrus"
	"github.com/caicloud/cauth/pkg/api/errors"
	"github.com/caicloud/cauth/pkg/api/v2"
	authv2 "github.com/caicloud/cauth/pkg/apis/auth/v2"
	"github.com/coreos/dex/connector"
)

type Config struct {
	Host string `json:"host"`
}

func (c *Config) Open(logger logrus.FieldLogger) (connector.Connector, error) {
	ca := cauthConnector{
		hostName: c.Host,
		logger:   logger,
	}
	return &ca, nil
}

type cauthConnector struct {
	hostName string
	logger   logrus.FieldLogger
}

// TODO(liubog2008): try to support session management
type connectorData struct {
	// store user id as a session
	UserID string `json:"userId"`
}

func (c *cauthConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (connector.Identity, bool, error) {
	if u, authed, err := c.auth(username, password); err != nil {
		return connector.Identity{}, false, err
	} else if !authed {
		return connector.Identity{}, false, nil
	} else if claim, err := c.getClaim(username); err != nil {
		return connector.Identity{}, false, err
	} else {
		data := connectorData{UserID: u.Username}
		connData, err := json.Marshal(data)
		if err != nil {
			return connector.Identity{}, false, err
		}
		return connector.Identity{
			UserID:        u.Username,
			Username:      u.Nickname,
			Email:         u.Email,
			EmailVerified: u.EmailVerified,
			Groups:        claim.Groups,
			CustomClaims: map[string]interface{}{
				"teams": claim.Teams,
			},
			ConnectorData: connData,
		}, true, nil
	}
}

func (c *cauthConnector) BindRemoteUser(connID string, identity *connector.Identity) (*connector.Identity, error) {
	if u, err := c.createRemoteUser(connID, identity); err != nil {
		return nil, err
	} else if claim, err := c.getClaim(u.Username); err != nil {
		return nil, err
	} else {
		return &connector.Identity{
			UserID:        u.Username,
			Username:      u.Nickname,
			Email:         u.Email,
			EmailVerified: u.EmailVerified,
			Groups:        claim.Groups,
			CustomClaims: map[string]interface{}{
				"teams": claim.Teams,
			},
		}, nil
	}
}

func (c *cauthConnector) RemoteUser(connID string, userID string) (*connector.Identity, error) {
	if u, err := c.getRemoteUser(connID, userID); err != nil {
		return nil, err
	} else if claim, err := c.getClaim(u.Username); err != nil {
		return nil, err
	} else {
		return &connector.Identity{
			UserID:        u.Username,
			Username:      u.Nickname,
			Email:         u.Email,
			EmailVerified: u.EmailVerified,
			Groups:        claim.Groups,
			CustomClaims: map[string]interface{}{
				"teams": claim.Teams,
			},
		}, nil
	}
}

func (c *cauthConnector) createRemoteUser(connID string, identity *connector.Identity) (*v2.User, error) {
	url := fmt.Sprintf("http://%s/api/v2/users", c.hostName)

	u := v2.User{
		Username:      identity.Username + "-" + identity.UserID[:5],
		Nickname:      identity.Username,
		Email:         identity.Email,
		EmailVerified: identity.EmailVerified,

		Remote:   connID,
		RemoteID: identity.UserID,
	}
	if body, err := json.Marshal(&u); err != nil {
		return nil, err
	} else if req, err := http.NewRequest("POST", url, bytes.NewBuffer(body)); err != nil {
		return nil, err
	} else {
		req.Header.Set("Content-Type", "application/json")
		if resp, err := http.DefaultClient.Do(req); err != nil {
			return nil, err
		} else {
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				return nil, fmt.Errorf("bind remote user error: status code is %s, not 201", resp.StatusCode)
			} else if created, err := ioutil.ReadAll(resp.Body); err != nil {
				return nil, err
			} else if err := json.Unmarshal(created, &u); err != nil {
				return nil, err
			} else {
				return &u, nil
			}
		}
	}

}

func (c *cauthConnector) getRemoteUser(connID string, userID string) (*v2.User, error) {
	url := fmt.Sprintf("http://%s/api/v2/users?remote=%s&remoteId=%s", c.hostName, connID, userID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	us := v2.UserList{}
	if body, err := ioutil.ReadAll(resp.Body); err != nil {
		return nil, err
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get remote user info error: status is %v", resp.StatusCode)
	} else if err := json.Unmarshal(body, &us); err != nil {
		return nil, err
	} else if len(us.Items) == 1 {
		u := us.Items[0]
		return &u, nil
	} else if len(us.Items) == 0 {
		return nil, nil
	} else {
		return nil, fmt.Errorf("get more than one identity: %v, connID: %v, userID: %v", len(us.Items), connID, userID)
	}
}

func (c *cauthConnector) getClaim(username string) (*v2.Claim, error) {
	url := fmt.Sprintf("http://%s/api/v2/claim?user=%s", c.hostName, username)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	claim := v2.Claim{}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	e := errors.Error{}
	if resp.StatusCode != http.StatusOK {
		if err := json.Unmarshal(body, &e); err != nil {
			return nil, err
		} else {
			return nil, &e
		}
	} else {
		if err := json.Unmarshal(body, &claim); err != nil {
			return nil, err
		} else {
			c.logger.Infof("cauth claim: %v", &claim)
			return &claim, nil
		}
	}

}

func (c *cauthConnector) auth(username string, password string) (*v2.User, bool, error) {
	url := fmt.Sprintf("http://%s/apis/auth/v2/authentication", c.hostName)
	a := authv2.Authentication{
		v2.User{
			Username: username,
			Password: password,
		},
	}
	if body, err := json.Marshal(&a); err != nil {
		return nil, false, err
	} else if req, err := http.NewRequest("POST", url, bytes.NewBuffer(body)); err != nil {
		return nil, false, err
	} else {
		req.Header.Set("Content-Type", "application/json")
		if resp, err := http.DefaultClient.Do(req); err != nil {
			return nil, false, err
		} else {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized {
				return nil, false, nil
			}

			authed, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, false, err
			}
			e := errors.Error{}

			if resp.StatusCode != http.StatusCreated {
				if err := json.Unmarshal(authed, &e); err != nil {
					return nil, false, err
				}
				return nil, false, &e
			} else {
				if err := json.Unmarshal(authed, &a); err != nil {
					return nil, false, err
				}
				return &a.User, true, nil
			}
		}
	}
}

func (c *cauthConnector) getUser(userID string) (*v2.User, error) {
	url := fmt.Sprintf("http://%s/api/v2/users/%s", c.hostName, userID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	u := v2.User{}
	if body, err := ioutil.ReadAll(resp.Body); err != nil {
		return nil, err
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get user info error: status is %v", resp.StatusCode)
	} else if err := json.Unmarshal(body, &u); err != nil {
		return nil, err
	} else {
		return &u, nil
	}
}

func (c *cauthConnector) Refresh(ctx context.Context, s connector.Scopes, ident connector.Identity) (connector.Identity, error) {
	c.logger.Infof("connector data %v", ident)
	if len(ident.ConnectorData) == 0 {
		return ident, fmt.Errorf("cauth: session has expired, please login again")
	}

	var data connectorData
	if err := json.Unmarshal(ident.ConnectorData, &data); err != nil {
		return ident, fmt.Errorf("cauth: unmarshal username: %v", err)
	}

	u, err := c.getUser(data.UserID)
	if err != nil {
		return ident, fmt.Errorf("cauth: can't get user info, user %v does not exists", data.UserID)
	}

	if claim, err := c.getClaim(data.UserID); err != nil {
		return connector.Identity{}, err
	} else {
		return connector.Identity{
			UserID:        u.Username,
			Username:      u.Nickname,
			Email:         u.Email,
			EmailVerified: u.EmailVerified,
			Groups:        claim.Groups,
			CustomClaims: map[string]interface{}{
				"teams": claim.Teams,
			},
			ConnectorData: ident.ConnectorData,
		}, nil
	}

}
