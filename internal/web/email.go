package web

import (
	"crypto/tls"
	"fmt"
	"html"
	"net"
	"net/smtp"
	"strings"

	"github.com/kaganyegin/server-side-control/internal/config"
	"github.com/kaganyegin/server-side-control/internal/domain"
)

func sendAutoDeployResultEmail(cfg config.Config, site domain.ManagedSite, branch string, result domain.DeploymentRelease, deployErr error) error {
	recipient := strings.TrimSpace(site.AutoDeployNotifyEmail)
	if recipient == "" {
		recipient = strings.TrimSpace(cfg.SMTPTo)
	}
	if strings.TrimSpace(cfg.SMTPHost) == "" || strings.TrimSpace(cfg.SMTPFrom) == "" || recipient == "" {
		return nil
	}
	port := strings.TrimSpace(cfg.SMTPPort)
	if port == "" {
		port = "587"
	}
	status := "success"
	bodyStatus := "completed successfully"
	output := result.Output
	if deployErr != nil {
		status = "failure"
		bodyStatus = "failed"
		output = strings.TrimSpace(output + "\n" + deployErr.Error())
	}
	subject := fmt.Sprintf("[Server Side Control] Auto deploy %s: %s (%s)", status, site.Name, branch)
	plainBody := strings.Join([]string{
		fmt.Sprintf("Site: %s", site.Name),
		fmt.Sprintf("Domain: %s", site.DomainName),
		fmt.Sprintf("Branch: %s", branch),
		fmt.Sprintf("Status: %s", bodyStatus),
		fmt.Sprintf("Action: %s", firstNonEmpty(result.Action, "deploy")),
		fmt.Sprintf("Commit: %s", firstNonEmpty(result.CommitSHA, "-")),
		fmt.Sprintf("Previous commit: %s", firstNonEmpty(result.PreviousCommitSHA, "-")),
		"",
		"Output:",
		firstNonEmpty(strings.TrimSpace(output), "No output captured."),
	}, "\n")
	htmlBody := buildAutoDeployHTMLBody(site, branch, bodyStatus, result, output)
	message := buildMultipartEmail(cfg.SMTPFrom, recipient, subject, plainBody, htmlBody)
	return sendSMTPMail(cfg, []string{recipient}, message)
}

func sendSMTPTestEmail(cfg config.Config) error {
	recipient := strings.TrimSpace(cfg.SMTPTo)
	if strings.TrimSpace(cfg.SMTPHost) == "" || strings.TrimSpace(cfg.SMTPFrom) == "" || recipient == "" {
		return fmt.Errorf("smtp host, from email and recipient are required")
	}
	plainBody := "SMTP test mail from Server Side Control.\n\nIf you received this message, SMTP settings are working."
	htmlBody := `<html><body style="font-family:Arial,sans-serif;color:#1f2937;"><h2>SMTP Test</h2><p>If you received this message, SMTP settings are working.</p></body></html>`
	message := buildMultipartEmail(cfg.SMTPFrom, recipient, "[Server Side Control] SMTP test", plainBody, htmlBody)
	return sendSMTPMail(cfg, []string{recipient}, message)
}

func buildMultipartEmail(from string, to string, subject string, plainBody string, htmlBody string) []byte {
	boundary := "ssc-boundary-20260326"
	message := strings.Join([]string{
		fmt.Sprintf("From: %s", from),
		fmt.Sprintf("To: %s", to),
		fmt.Sprintf("Subject: %s", subject),
		"MIME-Version: 1.0",
		fmt.Sprintf("Content-Type: multipart/alternative; boundary=%q", boundary),
		"",
		"--" + boundary,
		"Content-Type: text/plain; charset=UTF-8",
		"",
		plainBody,
		"--" + boundary,
		"Content-Type: text/html; charset=UTF-8",
		"",
		htmlBody,
		"--" + boundary + "--",
	}, "\r\n")
	return []byte(message)
}

func buildAutoDeployHTMLBody(site domain.ManagedSite, branch string, bodyStatus string, result domain.DeploymentRelease, output string) string {
	return fmt.Sprintf(`<html><body style="font-family:Arial,sans-serif;color:#1f2937;line-height:1.5;">
<h2 style="margin:0 0 12px;">Auto Deploy Result</h2>
<table style="border-collapse:collapse;width:100%%;max-width:760px;">
<tr><td style="padding:6px 10px;border:1px solid #d1d5db;"><strong>Site</strong></td><td style="padding:6px 10px;border:1px solid #d1d5db;">%s</td></tr>
<tr><td style="padding:6px 10px;border:1px solid #d1d5db;"><strong>Domain</strong></td><td style="padding:6px 10px;border:1px solid #d1d5db;">%s</td></tr>
<tr><td style="padding:6px 10px;border:1px solid #d1d5db;"><strong>Branch</strong></td><td style="padding:6px 10px;border:1px solid #d1d5db;">%s</td></tr>
<tr><td style="padding:6px 10px;border:1px solid #d1d5db;"><strong>Status</strong></td><td style="padding:6px 10px;border:1px solid #d1d5db;">%s</td></tr>
<tr><td style="padding:6px 10px;border:1px solid #d1d5db;"><strong>Action</strong></td><td style="padding:6px 10px;border:1px solid #d1d5db;">%s</td></tr>
<tr><td style="padding:6px 10px;border:1px solid #d1d5db;"><strong>Commit</strong></td><td style="padding:6px 10px;border:1px solid #d1d5db;">%s</td></tr>
<tr><td style="padding:6px 10px;border:1px solid #d1d5db;"><strong>Previous commit</strong></td><td style="padding:6px 10px;border:1px solid #d1d5db;">%s</td></tr>
</table>
<h3 style="margin:18px 0 8px;">Output</h3>
<pre style="background:#111827;color:#dbeafe;padding:14px;border-radius:8px;white-space:pre-wrap;">%s</pre>
</body></html>`,
		html.EscapeString(site.Name),
		html.EscapeString(site.DomainName),
		html.EscapeString(branch),
		html.EscapeString(bodyStatus),
		html.EscapeString(firstNonEmpty(result.Action, "deploy")),
		html.EscapeString(firstNonEmpty(result.CommitSHA, "-")),
		html.EscapeString(firstNonEmpty(result.PreviousCommitSHA, "-")),
		html.EscapeString(firstNonEmpty(strings.TrimSpace(output), "No output captured.")),
	)
}

func sendSMTPMail(cfg config.Config, recipients []string, message []byte) error {
	host := strings.TrimSpace(cfg.SMTPHost)
	port := strings.TrimSpace(cfg.SMTPPort)
	if port == "" {
		port = "587"
	}
	addr := net.JoinHostPort(host, port)
	var auth smtp.Auth
	if strings.TrimSpace(cfg.SMTPUsername) != "" {
		auth = smtp.PlainAuth("", cfg.SMTPUsername, cfg.SMTPPassword, host)
	}
	if port == "465" {
		conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host})
		if err != nil {
			return err
		}
		defer conn.Close()
		client, err := smtp.NewClient(conn, host)
		if err != nil {
			return err
		}
		defer client.Quit()
		if auth != nil {
			if err := client.Auth(auth); err != nil {
				return err
			}
		}
		return writeSMTPMessage(client, cfg.SMTPFrom, recipients, message)
	}
	client, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer client.Quit()
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: host}); err != nil {
			return err
		}
	}
	if auth != nil {
		if ok, _ := client.Extension("AUTH"); ok {
			if err := client.Auth(auth); err != nil {
				return err
			}
		}
	}
	return writeSMTPMessage(client, cfg.SMTPFrom, recipients, message)
}

func writeSMTPMessage(client *smtp.Client, from string, recipients []string, message []byte) error {
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, recipient := range recipients {
		if err := client.Rcpt(strings.TrimSpace(recipient)); err != nil {
			return err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return err
	}
	return writer.Close()
}