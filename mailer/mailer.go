package mailer

import (
	"bytes"
	"embed"
	"html/template"
	"time"

	"gopkg.in/mail.v2"
)

const (
	tmplEmailVerification = "email_verification.tmpl"
	tmplPasswordReset     = "password_reset.tmpl"
)

//go:embed "templates"
var templateFS embed.FS

type Mailer struct {
	dialer *mail.Dialer
	sender string
}

func NewMailer(dialer *mail.Dialer, sender string) *Mailer {
	return &Mailer{
		dialer: dialer,
		sender: sender,
	}
}

func (m *Mailer) send(recipient, mailType string, data any) error {
	tmpl, err := template.New("email").ParseFS(templateFS, "templates/"+mailType)
	if err != nil {
		return err
	}

	subject := new(bytes.Buffer)
	err = tmpl.ExecuteTemplate(subject, "subject", data)
	if err != nil {
		return err
	}

	textBody := new(bytes.Buffer)
	err = tmpl.ExecuteTemplate(textBody, "textBody", data)
	if err != nil {
		return err
	}

	htmlBody := new(bytes.Buffer)
	err = tmpl.ExecuteTemplate(htmlBody, "htmlBody", data)
	if err != nil {
		return err
	}

	msg := mail.NewMessage()
	msg.SetHeader("To", recipient)
	msg.SetHeader("From", m.sender)
	msg.SetHeader("Subject", subject.String())
	msg.SetBody("text/plain", textBody.String())
	msg.AddAlternative("text/html", htmlBody.String())

	for i := 1; i <= 3; i++ {
		err = m.dialer.DialAndSend(msg)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		return nil
	}

	return err
}

func (m *Mailer) SendVerificationEmail(recipient, token string) error {
	data := map[string]interface{}{
		"Code": token,
	}
	return m.send(recipient, tmplEmailVerification, data)
}

func (m *Mailer) SendPasswordResetEmail(recipient, token string) error {
	data := map[string]interface{}{
		"Code": token,
	}
	return m.send(recipient, tmplPasswordReset, data)
}
