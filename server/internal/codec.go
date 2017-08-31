package internal

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/golang/protobuf/proto"
)

// Marshal converts a protobuf message to a URL legal string.
func Marshal(message proto.Message) (string, error) {
	data, err := proto.Marshal(message)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// Unmarshal decodes a protobuf message.
func Unmarshal(s string, message proto.Message) error {
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	return proto.Unmarshal(data, message)
}

func (s *IDTokenSubject) Marshal() ([]byte, error) {
	return []byte(s.UserId + "-" + s.ConnId), nil
}

func (s *IDTokenSubject) Unmarshal(body []byte) error {
	sub := strings.Split(string(body), "-")
	if len(sub) != 2 {
		return fmt.Errorf("can't unmarshal %v to IDTokenSubject", string(body))
	}
	s.UserId = sub[0]
	s.ConnId = sub[1]
	return nil
}
