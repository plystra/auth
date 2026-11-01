package mail

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/plystra/auth/internal/secret"
	gomail "github.com/wneessen/go-mail"
)

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password secret.String
	From     string
}

type SMTPTransport struct{ config SMTPConfig }

func NewSMTPTransport(config SMTPConfig) (*SMTPTransport, error) {
	from, err := mail.ParseAddress(config.From)
	if strings.TrimSpace(config.Host) == "" || config.Port < 1 || config.Port > 65535 || err != nil || from.Address != config.From {
		return nil, errors.New("SMTP host, port, or sender address is invalid")
	}
	if (config.Username == "") != (config.Password.Value() == "") {
		return nil, errors.New("SMTP username and password must be configured together")
	}
	return &SMTPTransport{config: config}, nil
}

func (s *SMTPTransport) Send(ctx context.Context, to, subject, body string) error {
	if s == nil {
		return errors.New("SMTP sender is not configured")
	}
	options := []gomail.Option{
		gomail.WithPort(s.config.Port),
		gomail.WithTLSPortPolicy(gomail.TLSMandatory),
		gomail.WithTimeout(10 * time.Second),
	}
	if s.config.Username != "" {
		options = append(options,
			gomail.WithUsername(s.config.Username),
			gomail.WithPassword(s.config.Password.Value()),
			gomail.WithSMTPAuth(gomail.SMTPAuthPlain),
		)
	}
	client, err := gomail.NewClient(s.config.Host, options...)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	message := gomail.NewMsg()
	if err := message.From(s.config.From); err != nil {
		return err
	}
	if err := message.To(to); err != nil {
		return err
	}
	message.Subject(subject)
	message.SetBodyString(gomail.TypeTextPlain, body)
	return client.DialAndSendWithContext(ctx, message)
}
