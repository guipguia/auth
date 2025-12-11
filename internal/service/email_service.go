package service

import (
	"fmt"
	"log"
	"net/smtp"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"

	"github.com/guipguia/auth/internal/config"
	"github.com/guipguia/auth/internal/domain"
)

// EmailService handles sending emails
type EmailService interface {
	SendVerificationEmail(to, token string) error
	SendPasswordResetEmail(to, token string) error
	SendPasswordlessEmail(to, token string) error
	Send2FACode(to, code string) error
	SendWelcomeEmail(to, name string) error
	SendInvitationEmail(to, inviteLink string, role domain.MemberRole) error
}

type emailService struct {
	cfg             *config.EmailConfig
	templateManager *templateManager
	appURL          string
}

// NewEmailService creates a new email service
func NewEmailService(cfg *config.EmailConfig, appURL string) EmailService {
	// Initialize template manager
	tm, err := newTemplateManager(cfg.FromName)
	if err != nil {
		// Log error but continue - will use fallback templates
		log.Printf("[WARN] Failed to load email templates: %v", err)
		tm = nil
	}

	return &emailService{
		cfg:             cfg,
		templateManager: tm,
		appURL:          appURL,
	}
}

// SendVerificationEmail sends an email verification email
func (s *emailService) SendVerificationEmail(to, token string) error {
	subject := "Verify Your Email"

	verificationURL := fmt.Sprintf("%s/verify-email?token=%s", s.appURL, token)

	body, err := s.renderTemplate(TemplateVerification, EmailTemplateData{
		VerificationURL: verificationURL,
	})
	if err != nil {
		return fmt.Errorf("failed to render template: %w", err)
	}

	return s.sendEmail(to, subject, body)
}

// SendPasswordResetEmail sends a password reset email
func (s *emailService) SendPasswordResetEmail(to, token string) error {
	subject := "Reset Your Password"

	resetURL := fmt.Sprintf("%s/reset-password?token=%s", s.appURL, token)

	body, err := s.renderTemplate(TemplatePasswordReset, EmailTemplateData{
		ResetURL: resetURL,
	})
	if err != nil {
		return fmt.Errorf("failed to render template: %w", err)
	}

	return s.sendEmail(to, subject, body)
}

// SendPasswordlessEmail sends a passwordless login email
func (s *emailService) SendPasswordlessEmail(to, token string) error {
	subject := "Your Login Link"

	loginURL := fmt.Sprintf("%s/login?token=%s", s.appURL, token)

	body, err := s.renderTemplate(TemplatePasswordless, EmailTemplateData{
		LoginURL: loginURL,
	})
	if err != nil {
		return fmt.Errorf("failed to render template: %w", err)
	}

	return s.sendEmail(to, subject, body)
}

// Send2FACode sends a 2FA code via email
func (s *emailService) Send2FACode(to, code string) error {
	subject := "Your Two-Factor Authentication Code"

	body, err := s.renderTemplate(Template2FACode, EmailTemplateData{
		Code: code,
	})
	if err != nil {
		return fmt.Errorf("failed to render template: %w", err)
	}

	return s.sendEmail(to, subject, body)
}

// SendWelcomeEmail sends a welcome email to new users
func (s *emailService) SendWelcomeEmail(to, name string) error {
	subject := "Welcome!"

	body, err := s.renderTemplate(TemplateWelcome, EmailTemplateData{
		Name: name,
	})
	if err != nil {
		return fmt.Errorf("failed to render template: %w", err)
	}

	return s.sendEmail(to, subject, body)
}

// SendInvitationEmail sends a team invitation email
func (s *emailService) SendInvitationEmail(to, inviteLink string, role domain.MemberRole) error {
	subject := "You've been invited to join a team"

	body, err := s.renderTemplate(TemplateInvitation, EmailTemplateData{
		InviteURL: inviteLink,
		Role:      string(role),
	})
	if err != nil {
		return fmt.Errorf("failed to render template: %w", err)
	}

	return s.sendEmail(to, subject, body)
}

// sendEmail sends an email using the configured provider
func (s *emailService) sendEmail(to, subject, body string) error {
	switch s.cfg.Provider {
	case "smtp":
		return s.sendSMTPEmail(to, subject, body)
	case "sendgrid":
		return s.sendSendGridEmail(to, subject, body)
	case "ses":
		// Implement AWS SES integration
		return fmt.Errorf("ses provider not implemented yet")
	default:
		return fmt.Errorf("unknown email provider: %s", s.cfg.Provider)
	}
}

// sendSMTPEmail sends an email via SMTP
func (s *emailService) sendSMTPEmail(to, subject, body string) error {
	if s.cfg.SMTPHost == "" {
		// If SMTP is not configured, just log and return success
		// This allows the service to run without email configuration
		log.Printf("[DEBUG] Email would be sent to %s: %s", to, subject)
		log.Printf("[DEBUG] Body:\n%s", body)
		return nil
	}

	from := s.cfg.FromEmail
	auth := smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPass, s.cfg.SMTPHost)

	msg := []byte(fmt.Sprintf("From: %s <%s>\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"\r\n"+
		"%s\r\n", s.cfg.FromName, from, to, subject, body))

	addr := fmt.Sprintf("%s:%d", s.cfg.SMTPHost, s.cfg.SMTPPort)
	err := smtp.SendMail(addr, auth, from, []string{to}, msg)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// sendSendGridEmail sends an email via SendGrid
func (s *emailService) sendSendGridEmail(to, subject, body string) error {
	if s.cfg.APIKey == "" {
		// If SendGrid API key is not configured, just log and return success
		// This allows the service to run without email configuration
		log.Printf("[DEBUG] Email would be sent to %s: %s", to, subject)
		log.Printf("[DEBUG] Body:\n%s", body)
		return nil
	}

	from := mail.NewEmail(s.cfg.FromName, s.cfg.FromEmail)
	toEmail := mail.NewEmail("", to)

	// Create plain text content
	plainTextContent := mail.NewContent("text/plain", body)

	// Create the message
	message := mail.NewV3MailInit(from, subject, toEmail, plainTextContent)

	// Send the email
	client := sendgrid.NewSendClient(s.cfg.APIKey)
	response, err := client.Send(message)
	if err != nil {
		return fmt.Errorf("failed to send email via SendGrid: %w", err)
	}

	// Check response status
	if response.StatusCode >= 400 {
		return fmt.Errorf("SendGrid API error: status code %d, body: %s", response.StatusCode, response.Body)
	}

	return nil
}

// renderTemplate renders an email template with the given data
func (s *emailService) renderTemplate(tmpl EmailTemplate, data EmailTemplateData) (string, error) {
	if s.templateManager == nil {
		return "", fmt.Errorf("template manager not initialized")
	}
	return s.templateManager.render(tmpl, data)
}
