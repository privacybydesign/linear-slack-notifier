// Command linear-slack-notifier posts Linear issue events to Slack without
// their content.
//
// Linear's own Slack notifications include issue titles, descriptions and
// comments. For support tickets those contain customer data, so this service
// receives Linear's webhooks instead and posts only the identifier and what
// happened, e.g. "SUP-123 created", "SUP-123 → Done" or "SUP-123 reply
// received".
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	// maxBodySize bounds the webhook payload, which includes the full issue
	// description.
	maxBodySize = 5 << 20
	// maxClockSkew is how far a webhook's timestamp may be from now before it
	// is rejected as a possible replay.
	maxClockSkew = time.Minute
)

func main() {
	n, addr, err := fromEnv()
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("POST /webhook", n)
	mux.HandleFunc("GET /healthz", func(http.ResponseWriter, *http.Request) {})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("Listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

func fromEnv() (*notifier, string, error) {
	n := &notifier{
		secret:   []byte(os.Getenv("LINEAR_WEBHOOK_SECRET")),
		slackURL: os.Getenv("SLACK_WEBHOOK_URL"),
		teamKey:  os.Getenv("LINEAR_TEAM_KEY"),
		// Keep Slack delivery well within Linear's webhook response timeout.
		client: &http.Client{Timeout: 4 * time.Second},
		now:    time.Now,
	}
	if len(n.secret) == 0 {
		return nil, "", errors.New("LINEAR_WEBHOOK_SECRET is not set")
	}
	if n.slackURL == "" {
		return nil, "", errors.New("SLACK_WEBHOOK_URL is not set")
	}
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	return n, addr, nil
}

type notifier struct {
	secret   []byte
	slackURL string
	// teamKey, if set, limits notifications to issues of that team.
	teamKey string
	client  *http.Client
	now     func() time.Time
}

// event holds the fields of a Linear issue or comment webhook that this
// service uses. Titles, descriptions, comment bodies and other content are
// deliberately not decoded.
type event struct {
	Action           string  `json:"action"`
	Type             string  `json:"type"`
	WebhookTimestamp float64 `json:"webhookTimestamp"`
	Data             struct {
		issueRef
		State struct {
			Name string `json:"name"`
		} `json:"state"`

		// Set on comments.
		Issue          issueRef `json:"issue"`
		ExternalUserID string   `json:"externalUserId"`
	} `json:"data"`
	UpdatedFrom struct {
		StateID string `json:"stateId"`
	} `json:"updatedFrom"`
}

type issueRef struct {
	Identifier string `json:"identifier"`
	URL        string `json:"url"`
	Team       struct {
		Key string `json:"key"`
	} `json:"team"`
}

// issue returns the issue that e is about.
func (e *event) issue() issueRef {
	if e.Type == "Comment" {
		return e.Data.Issue
	}
	return e.Data.issueRef
}

func (n *notifier) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodySize))
	if err != nil {
		http.Error(w, "could not read body", http.StatusBadRequest)
		return
	}
	if !validSignature(n.secret, body, r.Header.Get("Linear-Signature")) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	var e event
	if err := json.Unmarshal(body, &e); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	if n.now().Sub(time.UnixMilli(int64(e.WebhookTimestamp))).Abs() > maxClockSkew {
		http.Error(w, "stale webhook", http.StatusUnauthorized)
		return
	}

	text, ok := n.message(&e)
	if !ok {
		return
	}
	id := e.issue().Identifier
	if err := n.postToSlack(r.Context(), text); err != nil {
		// A non-2xx response makes Linear retry the delivery later.
		log.Printf("%s: posting to Slack failed: %v", id, err)
		http.Error(w, "slack delivery failed", http.StatusBadGateway)
		return
	}
	log.Printf("%s: posted %s %s", id, e.Type, e.Action)
}

// message returns the Slack text for e, or false if e should not be posted.
func (n *notifier) message(e *event) (string, bool) {
	var what string
	switch {
	case e.Type == "Issue" && e.Action == "create":
		what = "created"
	case e.Type == "Issue" && e.Action == "update" && e.UpdatedFrom.StateID != "":
		what = "→ " + slackEscape(e.Data.State.Name)
	// Comments by external users come from outside Linear, such as a
	// customer replying by email.
	case e.Type == "Comment" && e.Action == "create" && e.Data.ExternalUserID != "":
		what = "reply received"
	default:
		return "", false
	}

	issue := e.issue()
	if n.teamKey != "" && !strings.EqualFold(issue.Team.Key, n.teamKey) {
		return "", false
	}
	return "<" + issue.URL + "|" + slackEscape(issue.Identifier) + "> " + what, true
}

// validSignature reports whether signature is the hex-encoded HMAC-SHA256 of
// body, which is how Linear signs its webhooks.
func validSignature(secret, body []byte, signature string) bool {
	got, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}

func (n *notifier) postToSlack(ctx context.Context, text string) error {
	body, err := json.Marshal(map[string]any{
		"text": text,
		// An unfurl of the issue link would show the title and description,
		// which is exactly what this service keeps out of Slack.
		"unfurl_links": false,
		"unfurl_media": false,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.slackURL, bytes.NewReader(body))
	if err != nil {
		return redact(err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := n.client.Do(req)
	if err != nil {
		return redact(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return fmt.Errorf("slack responded %s: %s", res.Status, msg)
	}
	return nil
}

// redact strips the request URL from err. The Slack webhook URL is itself the
// credential, and net/http includes it in its errors.
func redact(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return fmt.Errorf("%s: %w", uerr.Op, uerr.Err)
	}
	return err
}

func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
