package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var recaptchaVerifyURL = "https://www.google.com/recaptcha/api/siteverify"

// setRecaptchaVerifyURL overrides the verification endpoint (for testing).
func setRecaptchaVerifyURL(u string) { recaptchaVerifyURL = u }

type recaptchaResponse struct {
	Success bool    `json:"success"`
	Score   float64 `json:"score"`
	Action  string  `json:"action"`
}

// verifyRecaptcha validates a reCAPTCHA v3 token with Google's siteverify API.
// If secretKey is empty, it returns 1.0 (graceful skip for dev environments).
func verifyRecaptcha(ctx context.Context, secretKey, token, remoteIP string) (float64, error) {
	if secretKey == "" {
		return 1.0, nil
	}

	client := &http.Client{Timeout: 5 * time.Second}

	form := url.Values{
		"secret":   {secretKey},
		"response": {token},
		"remoteip": {remoteIP},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, recaptchaVerifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, fmt.Errorf("creating recaptcha request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("recaptcha verification request failed: %w", err)
	}
	defer resp.Body.Close()

	var result recaptchaResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("decoding recaptcha response: %w", err)
	}

	if !result.Success {
		return 0, nil
	}

	return result.Score, nil
}
