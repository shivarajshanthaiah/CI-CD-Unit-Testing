package auth

import (
	"log"
	"math/rand"
	"net/smtp"
	"os"
	"time"
)

// GenerateOTP function generates desired length one time password
func GenerateOTP(length int) string {
	rand.NewSource(time.Now().UnixNano())
	characters := "0123456789"
	otp := make([]byte, length)
	for i := range otp {
		otp[i] = characters[rand.Intn(len(characters))]
	}

	return string(otp)
}

// SendOTPByEmail function send the generated otp to user email
func SendOTPByEmail(otp, email string) error {

	message := "Subject: WebPortal OTP\nHey Your OTP is " + otp

	SMTPemail := os.Getenv("Email")
	SMTPpass := os.Getenv("Password")
	auth := smtp.PlainAuth("", SMTPemail, SMTPpass, "smtp.gmail.com")

	err := smtp.SendMail("smtp.gmail.com:587", auth, SMTPemail, []string{email}, []byte(message))
	if err != nil {
		log.Println("Error sending email:", err)
		return err
	}

	return nil
}

// ValidateOTP validates the saved otp and user entered otp
func ValidateOTP(otp, userOTP string) bool {
	return otp == userOTP
}
