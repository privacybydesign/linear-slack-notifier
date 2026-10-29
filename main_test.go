package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	testSecret = "test-secret"
	issueURL   = "https://linear.app/yivi/issue/SUP-12/vraag-van-jan-jansen"
)

var testNow = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

type slackStub struct {
	*httptest.Server
	payloads []map[string]any
}

func newSlackStub(t *testing.T, status int) *slackStub {
	t.Helper()
	s := &slackStub{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p map[string]any
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Errorf("decoding Slack payload: %v", err)
		}
		s.payloads = append(s.payloads, p)
		w.WriteHeader(status)
	}))
	t.Cleanup(s.Close)
	return s
}

func newTestNotifier(slackURL string) *notifier {
	return &notifier{
		secret:   []byte(testSecret),
		slackURL: slackURL,
		teamKey:  "SUP",
		client:   &http.Client{Timeout: time.Second},
		now:      func() time.Time { return testNow },
	}
}

// issueEvent returns a Linear issue webhook whose content includes personal
// data that must never reach Slack.
func issueEvent(action string) map[string]any {
	return map[string]any{
		"action":           action,
		"type":             "Issue",
		"url":              issueURL,
		"webhookTimestamp": testNow.UnixMilli(),
		"data": map[string]any{
			"identifier":  "SUP-12",
			"number":      12,
			"url":         issueURL,
			"title":       "Vraag van Jan Jansen",
			"description": "Mijn e-mailadres is jan@example.com",
			"team":        map[string]any{"key": "SUP"},
			"state":       map[string]any{"name": "Done"},
		},
	}
}

// commentEvent returns a Linear webhook for a comment by a customer who
// replied by email.
func commentEvent() map[string]any {
	return map[string]any{
		"action":           "create",
		"type":             "Comment",
		"url":              issueURL + "#comment-1234",
		"webhookTimestamp": testNow.UnixMilli(),
		"data": map[string]any{
			"body":           "Hoi, het werkt weer. Groet, Jan Jansen",
			"externalUserId": "external-user-id",
			"externalUser":   map[string]any{"name": "Jan Jansen", "email": "jan@example.com"},
			"issue": map[string]any{
				"identifier": "SUP-12",
				"url":        issueURL,
				"title":      "Vraag van Jan Jansen",
				"team":       map[string]any{"key": "SUP"},
			},
		},
	}
}

func sign(body []byte) string {
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func deliver(t *testing.T, n *notifier, ev map[string]any, signature func([]byte) string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("Linear-Signature", signature(body))
	rec := httptest.NewRecorder()
	n.ServeHTTP(rec, req)
	return rec
}

func TestMessages(t *testing.T) {
	tests := []struct {
		name   string
		event  map[string]any
		modify func(ev map[string]any)
		want   string // empty if nothing should be posted
	}{
		{
			name:  "issue created",
			event: issueEvent("create"),
			want:  "<" + issueURL + "|SUP-12> created",
		},
		{
			name:  "status changed",
			event: issueEvent("update"),
			modify: func(ev map[string]any) {
				ev["updatedFrom"] = map[string]any{"stateId": "previous-state"}
			},
			want: "<" + issueURL + "|SUP-12> → Done",
		},
		{
			name:  "other field changed",
			event: issueEvent("update"),
			modify: func(ev map[string]any) {
				ev["updatedFrom"] = map[string]any{"title": "Vraag"}
			},
		},
		{
			name:  "issue removed",
			event: issueEvent("remove"),
		},
		{
			name:  "issue in other team",
			event: issueEvent("create"),
			modify: func(ev map[string]any) {
				ev["data"].(map[string]any)["team"] = map[string]any{"key": "YIV"}
			},
		},
		{
			name:  "customer reply",
			event: commentEvent(),
			want:  "<" + issueURL + "|SUP-12> reply received",
		},
		{
			name:  "comment by team member",
			event: commentEvent(),
			modify: func(ev map[string]any) {
				data := ev["data"].(map[string]any)
				delete(data, "externalUserId")
				delete(data, "externalUser")
				data["userId"] = "linear-user-id"
			},
		},
		{
			name:  "customer reply edited",
			event: commentEvent(),
			modify: func(ev map[string]any) {
				ev["action"] = "update"
			},
		},
		{
			name:  "customer reply in other team",
			event: commentEvent(),
			modify: func(ev map[string]any) {
				issue := ev["data"].(map[string]any)["issue"].(map[string]any)
				issue["team"] = map[string]any{"key": "YIV"}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slack := newSlackStub(t, http.StatusOK)
			ev := tt.event
			if tt.modify != nil {
				tt.modify(ev)
			}

			rec := deliver(t, newTestNotifier(slack.URL), ev, sign)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}
			if tt.want == "" {
				if len(slack.payloads) != 0 {
					t.Fatalf("posted %v, want nothing", slack.payloads)
				}
				return
			}
			if len(slack.payloads) != 1 {
				t.Fatalf("posted %d messages, want 1", len(slack.payloads))
			}
			p := slack.payloads[0]
			if p["text"] != tt.want {
				t.Errorf("text = %q, want %q", p["text"], tt.want)
			}
			if p["unfurl_links"] != false || p["unfurl_media"] != false {
				t.Errorf("unfurls not disabled: %v", p)
			}
		})
	}
}

func TestRejectsInvalidSignature(t *testing.T) {
	slack := newSlackStub(t, http.StatusOK)

	rec := deliver(t, newTestNotifier(slack.URL), issueEvent("create"), func([]byte) string {
		return hex.EncodeToString([]byte("forged"))
	})

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if len(slack.payloads) != 0 {
		t.Errorf("posted %v, want nothing", slack.payloads)
	}
}

func TestRejectsStaleWebhook(t *testing.T) {
	slack := newSlackStub(t, http.StatusOK)
	ev := issueEvent("create")
	ev["webhookTimestamp"] = testNow.Add(-2 * maxClockSkew).UnixMilli()

	rec := deliver(t, newTestNotifier(slack.URL), ev, sign)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if len(slack.payloads) != 0 {
		t.Errorf("posted %v, want nothing", slack.payloads)
	}
}

func TestSlackFailureMakesLinearRetry(t *testing.T) {
	slack := newSlackStub(t, http.StatusInternalServerError)

	rec := deliver(t, newTestNotifier(slack.URL), issueEvent("create"), sign)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
}

func TestSlackErrorsDoNotContainWebhookURL(t *testing.T) {
	// Nothing listens on port 1, so the request fails with a *url.Error.
	n := newTestNotifier("http://127.0.0.1:1/services/T000/B000/webhook-token")

	err := n.postToSlack(context.Background(), "SUP-12 created")

	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "webhook-token") {
		t.Errorf("error leaks the webhook URL: %v", err)
	}
}
