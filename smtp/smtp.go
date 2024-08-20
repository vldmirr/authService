package smtplib

import (
	"authenticationService/app"
	"authenticationService/config"
	"authenticationService/logger"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/smtp"
)

func New(cfg config.SMTP) smtp.Auth {
	smtpHost := cfg.Host
	publicKey := cfg.PublicKey
	privateKey := cfg.PrivateKey

	auth := smtp.PlainAuth("", publicKey, privateKey, smtpHost)

	return auth
}

func SendEmail(a app.App, to, subject, body string) error {
	const name_process = "smtp.SendEmail"

	log := a.Logger.With(
		slog.String("op", name_process),
	)

	subject = "Subject: " + subject

	smtpHost := a.Config.SMTP.Host
	smtpPort := a.Config.SMTP.Port
	senderEmail := a.Config.SMTP.SenderEmail

	conn, err := smtp.Dial(smtpHost + ":" + smtpPort)
	if err != nil {
		return fmt.Errorf("%s: error connecting to SMTP server: %v", name_process, err)
	}
	defer func(conn *smtp.Client) {
		err := conn.Quit()
		if err != nil {
			log.Error("error closing connection", logger.Err(err))
		}
	}(conn)

	tlsConfig := &tls.Config{
		ServerName:         smtpHost,
		InsecureSkipVerify: true,
	}

	if err = conn.StartTLS(tlsConfig); err != nil {
		return fmt.Errorf("%s: error starting TLS: %v", name_process, err)
	}

	if err = conn.Auth(a.SMTP); err != nil {
		return fmt.Errorf("%s: error during authentication: %v", name_process, err)
	}

	if err = conn.Mail(senderEmail); err != nil {
		return fmt.Errorf("%s: error setting sender: %v", name_process, err)
	}

	if err = conn.Rcpt(to); err != nil {
		return fmt.Errorf("%s: error adding recipient: %v", name_process, err)
	}

	msg := []byte(subject + "\n" + body)

	w, err := conn.Data()
	if err != nil {
		return fmt.Errorf("%s: error sending data: %v", name_process, err)
	}
	_, err = w.Write(msg)
	if err != nil {
		return fmt.Errorf("%s: error writing message: %v", name_process, err)
	}
	err = w.Close()
	if err != nil {
		return fmt.Errorf("%s: error closing connection: %v", name_process, err)
	}

	log.Info("email sent successfully")

	return nil
}
