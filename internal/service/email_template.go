package service

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"text/template"
)

// Note: embed paths are relative to the module root
// We'll load templates at runtime instead of embedding

// EmailTemplate represents an email template type
type EmailTemplate string

const (
	TemplateVerification  EmailTemplate = "verification.txt"
	TemplatePasswordReset EmailTemplate = "password_reset.txt"
	TemplatePasswordless  EmailTemplate = "passwordless.txt"
	Template2FACode       EmailTemplate = "2fa_code.txt"
	TemplateWelcome       EmailTemplate = "welcome.txt"
	TemplateInvitation    EmailTemplate = "invitation.txt"
)

// EmailTemplateData holds the data for email templates
type EmailTemplateData struct {
	AppName         string
	VerificationURL string
	ResetURL        string
	LoginURL        string
	InviteURL       string
	Code            string
	Name            string
	Role            string
}

// templateManager handles email template rendering
type templateManager struct {
	templates map[EmailTemplate]*template.Template
	appName   string
}

// newTemplateManager creates a new template manager
func newTemplateManager(appName string) (*templateManager, error) {
	tm := &templateManager{
		templates: make(map[EmailTemplate]*template.Template),
		appName:   appName,
	}

	// Load all templates
	templates := []EmailTemplate{
		TemplateVerification,
		TemplatePasswordReset,
		TemplatePasswordless,
		Template2FACode,
		TemplateWelcome,
		TemplateInvitation,
	}

	// Get template directory path
	templateDir := filepath.Join("templates", "email")

	for _, tmpl := range templates {
		templatePath := filepath.Join(templateDir, string(tmpl))

		content, err := os.ReadFile(templatePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read template %s: %w", tmpl, err)
		}

		t, err := template.New(string(tmpl)).Parse(string(content))
		if err != nil {
			return nil, fmt.Errorf("failed to parse template %s: %w", tmpl, err)
		}

		tm.templates[tmpl] = t
	}

	return tm, nil
}

// render renders a template with the given data
func (tm *templateManager) render(tmpl EmailTemplate, data EmailTemplateData) (string, error) {
	t, ok := tm.templates[tmpl]
	if !ok {
		return "", fmt.Errorf("template %s not found", tmpl)
	}

	// Set default app name if not provided
	if data.AppName == "" {
		data.AppName = tm.appName
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}
