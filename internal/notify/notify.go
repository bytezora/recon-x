package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Config struct {
	SlackWebhook   string
	TelegramToken  string
	TelegramChatID string
}

func (c *Config) Enabled() bool {
	return c.SlackWebhook != "" || (c.TelegramToken != "" && c.TelegramChatID != "")
}

func (c *Config) Send(title, body string) {
	if c.SlackWebhook != "" {
		sendSlack(c.SlackWebhook, title, body)
	}
	if c.TelegramToken != "" && c.TelegramChatID != "" {
		sendTelegram(c.TelegramToken, c.TelegramChatID, title, body)
	}
}

func sendSlack(webhook, title, body string) {
	payload := map[string]interface{}{
		"text": fmt.Sprintf("*%s*\n%s", title, body),
	}
	b, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 10 * time.Second}
	client.Post(webhook, "application/json", bytes.NewReader(b)) //nolint:errcheck
}

func sendTelegram(token, chatID, title, body string) {
	text := fmt.Sprintf("*%s*\n%s", title, escapeMarkdown(body))
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	payload := map[string]string{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "Markdown",
	}
	b, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 10 * time.Second}
	client.Post(apiURL, "application/json", bytes.NewReader(b)) //nolint:errcheck
}

func escapeMarkdown(s string) string {
	replacer := strings.NewReplacer(
		"_", "\\_", "*", "\\*", "[", "\\[", "]", "\\]",
		"(", "\\(", ")", "\\)", "~", "\\~", "`", "\\`",
		">", "\\>", "#", "\\#", "+", "\\+", "-", "\\-",
		"=", "\\=", "|", "\\|", "{", "\\{", "}", "\\}",
		".", "\\.", "!", "\\!",
	)
	return replacer.Replace(s)
}
