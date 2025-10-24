// Package vaultwarden provides CLI-based secret retrieval
package vaultwarden

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/thijsherman/vaultwarden-api/pkg/logger"
)

type BitwardenItem struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Type   int    `json:"type"`
	Login  *struct {
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"login,omitempty"`
	Notes  string `json:"notes,omitempty"`
	Fields []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"fields,omitempty"`
}

func (c *Client) FetchSecretViaCLI(name string) (string, error) {
	if len(name) == 0 || len(name) > 255 {
		return "", fmt.Errorf("invalid secret name length")
	}

	for _, ch := range name {
		if !((ch >= 'a' && ch <= 'z') ||
		     (ch >= 'A' && ch <= 'Z') ||
		     (ch >= '0' && ch <= '9') ||
		     ch == '-' || ch == '_' || ch == '.' || ch == '/') {
			return "", fmt.Errorf("invalid character in secret name")
		}
	}

	cmd := exec.Command("bw", "get", "item", name)
	cmd.Env = append(os.Environ(), fmt.Sprintf("BW_SESSION=%s", c.token))
	output, err := cmd.Output()

	if err != nil {
		logger.Info.Printf("Exact match failed, searching for: %s", name)

		searchCmd := exec.Command("bw", "list", "items", "--search", name)
		searchCmd.Env = append(os.Environ(), fmt.Sprintf("BW_SESSION=%s", c.token))
		searchOutput, searchErr := searchCmd.Output()
		if searchErr != nil {
			return "", fmt.Errorf("failed to search for item: %w", searchErr)
		}

		var items []BitwardenItem
		if err := json.Unmarshal(searchOutput, &items); err != nil {
			return "", fmt.Errorf("failed to parse search results: %w", err)
		}

		if len(items) == 0 {
			return "", fmt.Errorf("secret not found: %s", name)
		}

		if len(items) > 1 {
			logger.Warn.Printf("Multiple items found for '%s', using first match: '%s' (ID: %s)", name, items[0].Name, items[0].ID)
		}

		output, err = json.Marshal(items[0])
		if err != nil {
			return "", fmt.Errorf("failed to marshal item: %w", err)
		}
	}

	var item BitwardenItem
	if err := json.Unmarshal(output, &item); err != nil {
		return "", fmt.Errorf("failed to parse item: %w", err)
	}

	return c.extractValueFromItem(item)
}

func (c *Client) extractValueFromItem(item BitwardenItem) (string, error) {
	if item.Login != nil && item.Login.Password != "" {
		return item.Login.Password, nil
	}

	for _, field := range item.Fields {
		fieldName := strings.ToLower(field.Name)
		if fieldName == "value" || fieldName == "secret" || fieldName == "api_key" {
			return field.Value, nil
		}
	}

	if item.Notes != "" {
		return item.Notes, nil
	}

	if len(item.Fields) > 0 {
		return item.Fields[0].Value, nil
	}

	return "", fmt.Errorf("no secret value found in item")
}

func (c *Client) SyncVault() error {
	cmd := exec.Command("bw", "sync")
	cmd.Env = append(os.Environ(), fmt.Sprintf("BW_SESSION=%s", c.token))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to sync vault: %w, output: %s", err, output)
	}
	logger.Info.Println("Vault synced successfully")
	return nil
}