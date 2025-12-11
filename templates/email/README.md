# Email Templates

This directory contains email templates used by the auth service. Templates use Go's `text/template` syntax.

## Available Templates

### 1. `verification.txt`
Used for email verification after registration.

**Available variables:**
- `{{ .VerificationURL }}` - The verification link
- `{{ .AppName }}` - Your application name

### 2. `password_reset.txt`
Used for password reset requests.

**Available variables:**
- `{{ .ResetURL }}` - The password reset link
- `{{ .AppName }}` - Your application name

### 3. `passwordless.txt`
Used for passwordless login (magic link).

**Available variables:**
- `{{ .LoginURL }}` - The login link
- `{{ .AppName }}` - Your application name

### 4. `2fa_code.txt`
Used for sending 2FA codes via email.

**Available variables:**
- `{{ .Code }}` - The 2FA code
- `{{ .AppName }}` - Your application name

### 5. `welcome.txt`
Used for welcoming new users.

**Available variables:**
- `{{ .Name }}` - User's name
- `{{ .AppName }}` - Your application name

## Customization

### Text Templates

Edit the `.txt` files directly. They use plain text format.

**Example:**
```
Hello,

Welcome to {{ .AppName }}!

Your verification link: {{ .VerificationURL }}

Thanks,
The Team
```

### HTML Templates (Future)

To add HTML email support:
1. Create `.html` versions of the templates (e.g., `verification.html`)
2. Update the email service to support HTML content type
3. SendGrid will automatically use HTML when provided

### Template Syntax

Go templates support:
- Variables: `{{ .VariableName }}`
- Conditionals: `{{ if .Variable }}...{{ end }}`
- Loops: `{{ range .Items }}...{{ end }}`
- Functions: `{{ .Variable | upper }}`

**Example with conditional:**
```
Hello{{ if .Name }} {{ .Name }}{{ end }},

{{ if .VerificationURL }}
Please verify: {{ .VerificationURL }}
{{ else }}
Your account is verified!
{{ end }}
```

## Configuration

The app name used in templates comes from the email configuration:

```yaml
email:
  from_name: "My App"  # This becomes {{ .AppName }} in templates
```

Or via environment variable:
```bash
AUTH_EMAIL_FROM_NAME="My App"
```

## Deployment

Templates are loaded at runtime, so you can:
1. Mount a volume with custom templates in Docker
2. Update templates without rebuilding the application
3. Use different templates for different environments

**Docker example:**
```yaml
volumes:
  - ./custom-templates:/home/appuser/templates
```

## Testing Templates

You can test template rendering by registering a user and checking the email output.

For development (without SendGrid), emails are printed to console so you can verify the rendered content.
