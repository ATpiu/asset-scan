package models

import (
	"asset-scan/lib"
	"crypto/tls"
	"gopkg.in/gomail.v2"
)

func SendMail(mail Mail, subject string, body string) (err error) {
	m := gomail.NewDialer(mail.Host, mail.Port, mail.Username, mail.Passwrod)
	m.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	msg := gomail.NewMessage()

	msg.SetAddressHeader("From", mail.From, "")
	msg.SetHeader("To", mail.To...)
	msg.SetHeader("Subject", subject)
	msg.SetBody("text/html", body)

	if err = m.DialAndSend(msg); err != nil {
		lib.FatalError("sendMail:" + err.Error())
	}
	return
}
