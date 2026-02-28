package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	lark "github.com/larksuite/oapi-sdk-go/v3"
	larkcore "github.com/larksuite/oapi-sdk-go/v3/core"
	"github.com/larksuite/oapi-sdk-go/v3/event/dispatcher"
	larkim "github.com/larksuite/oapi-sdk-go/v3/service/im/v1"
	larkws "github.com/larksuite/oapi-sdk-go/v3/ws"
)

type bridgeConfig struct {
	appID              string
	appSecret          string
	verificationToken  string
	encryptKey         string
	useLarkSuite       bool
	nullclawWebhookURL string
	requestTimeout     time.Duration
	logLevel           larkcore.LogLevel
}

func loadConfigFromEnv() (bridgeConfig, error) {
	appID := strings.TrimSpace(os.Getenv("FEISHU_APP_ID"))
	if appID == "" {
		return bridgeConfig{}, errors.New("missing FEISHU_APP_ID")
	}
	appSecret := strings.TrimSpace(os.Getenv("FEISHU_APP_SECRET"))
	if appSecret == "" {
		return bridgeConfig{}, errors.New("missing FEISHU_APP_SECRET")
	}

	webhookURL := strings.TrimSpace(os.Getenv("NULLCLAW_LARK_WEBHOOK_URL"))
	if webhookURL == "" {
		webhookURL = "http://127.0.0.1:3000/lark"
	}

	timeoutSecs := 10
	if raw := strings.TrimSpace(os.Getenv("NULLCLAW_REQUEST_TIMEOUT_SECS")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			return bridgeConfig{}, fmt.Errorf("invalid NULLCLAW_REQUEST_TIMEOUT_SECS: %q", raw)
		}
		timeoutSecs = parsed
	}

	useLarkSuite := parseBoolEnv("FEISHU_USE_LARKSUITE", false)

	level, err := parseLogLevel(strings.TrimSpace(os.Getenv("BRIDGE_LOG_LEVEL")))
	if err != nil {
		return bridgeConfig{}, err
	}

	return bridgeConfig{
		appID:              appID,
		appSecret:          appSecret,
		verificationToken:  strings.TrimSpace(os.Getenv("FEISHU_VERIFICATION_TOKEN")),
		encryptKey:         strings.TrimSpace(os.Getenv("FEISHU_ENCRYPT_KEY")),
		useLarkSuite:       useLarkSuite,
		nullclawWebhookURL: webhookURL,
		requestTimeout:     time.Duration(timeoutSecs) * time.Second,
		logLevel:           level,
	}, nil
}

func parseBoolEnv(key string, defaultValue bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if raw == "" {
		return defaultValue
	}
	switch raw {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return defaultValue
	}
}

func parseLogLevel(raw string) (larkcore.LogLevel, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "info":
		return larkcore.LogLevelInfo, nil
	case "debug":
		return larkcore.LogLevelDebug, nil
	case "warn", "warning":
		return larkcore.LogLevelWarn, nil
	case "error":
		return larkcore.LogLevelError, nil
	default:
		return 0, fmt.Errorf("invalid BRIDGE_LOG_LEVEL: %q (allowed: debug|info|warn|error)", raw)
	}
}

type forwarder struct {
	client *http.Client
	url    string
}

func (f *forwarder) postJSON(ctx context.Context, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return fmt.Errorf("nullclaw /lark returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
}

type deduper struct {
	mu   sync.Mutex
	seen map[string]time.Time
	ttl  time.Duration
}

func newDeduper(ttl time.Duration) *deduper {
	return &deduper{
		seen: make(map[string]time.Time),
		ttl:  ttl,
	}
}

func (d *deduper) seenRecently(messageID string) bool {
	if strings.TrimSpace(messageID) == "" {
		return false
	}

	now := time.Now()

	d.mu.Lock()
	defer d.mu.Unlock()

	for key, ts := range d.seen {
		if now.Sub(ts) > d.ttl {
			delete(d.seen, key)
		}
	}

	if ts, exists := d.seen[messageID]; exists {
		if now.Sub(ts) <= d.ttl {
			return true
		}
	}

	d.seen[messageID] = now
	return false
}

func valueOrEmpty(ptr *string) string {
	if ptr == nil {
		return ""
	}
	return *ptr
}

func buildFallbackPayload(event *larkim.P2MessageReceiveV1, fallbackToken string) ([]byte, error) {
	if event == nil || event.Event == nil || event.Event.Message == nil {
		return nil, errors.New("empty event payload")
	}

	msg := event.Event.Message
	sender := event.Event.Sender
	if sender == nil || sender.SenderId == nil || sender.SenderId.OpenId == nil || strings.TrimSpace(*sender.SenderId.OpenId) == "" {
		return nil, errors.New("event sender open_id is missing")
	}

	openID := strings.TrimSpace(*sender.SenderId.OpenId)
	messageType := strings.TrimSpace(valueOrEmpty(msg.MessageType))
	if messageType == "" {
		messageType = "text"
	}

	content := valueOrEmpty(msg.Content)
	if strings.TrimSpace(content) == "" {
		content = "{\"text\":\"\"}"
	}

	chatType := strings.TrimSpace(valueOrEmpty(msg.ChatType))
	if chatType == "" {
		chatType = "p2p"
	}

	chatID := strings.TrimSpace(valueOrEmpty(msg.ChatId))
	if chatID == "" {
		chatID = openID
	}

	createTime := strings.TrimSpace(valueOrEmpty(msg.CreateTime))
	if createTime == "" {
		createTime = strconv.FormatInt(time.Now().UnixMilli(), 10)
	}

	mentions := make([]map[string]any, 0, len(msg.Mentions))
	for _, mention := range msg.Mentions {
		if mention == nil {
			continue
		}
		item := map[string]any{}
		if mention.Key != nil && strings.TrimSpace(*mention.Key) != "" {
			item["key"] = *mention.Key
		}
		if mention.Id != nil {
			idObj := map[string]any{}
			if mention.Id.OpenId != nil && strings.TrimSpace(*mention.Id.OpenId) != "" {
				idObj["open_id"] = *mention.Id.OpenId
			}
			if mention.Id.UserId != nil && strings.TrimSpace(*mention.Id.UserId) != "" {
				idObj["user_id"] = *mention.Id.UserId
			}
			if mention.Id.UnionId != nil && strings.TrimSpace(*mention.Id.UnionId) != "" {
				idObj["union_id"] = *mention.Id.UnionId
			}
			if len(idObj) > 0 {
				item["id"] = idObj
			}
		}
		if len(item) > 0 {
			mentions = append(mentions, item)
		}
	}

	header := map[string]any{
		"event_type": "im.message.receive_v1",
	}
	if fallbackToken != "" {
		header["token"] = fallbackToken
	}

	messageObj := map[string]any{
		"message_type": messageType,
		"content":      content,
		"chat_type":    chatType,
		"chat_id":      chatID,
		"create_time":  createTime,
	}
	if len(mentions) > 0 {
		messageObj["mentions"] = mentions
	}

	body := map[string]any{
		"header": header,
		"event": map[string]any{
			"sender": map[string]any{
				"sender_id": map[string]any{
					"open_id": openID,
				},
			},
			"message": messageObj,
		},
	}

	return json.Marshal(body)
}

func normalizeWebhookPayload(raw []byte, fallbackToken string) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty payload")
	}

	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("decode raw event payload: %w", err)
	}

	headerObj, ok := body["header"].(map[string]any)
	if !ok {
		headerObj = map[string]any{}
		body["header"] = headerObj
	}

	if _, hasType := headerObj["event_type"]; !hasType {
		if parsedType, ok := body["type"].(string); ok && strings.TrimSpace(parsedType) != "" {
			headerObj["event_type"] = parsedType
		}
	}

	if fallbackToken != "" {
		token, _ := headerObj["token"].(string)
		if strings.TrimSpace(token) == "" {
			headerObj["token"] = fallbackToken
		}
	}

	return json.Marshal(body)
}

func messageHandler(cfg bridgeConfig, fw *forwarder, dd *deduper) func(context.Context, *larkim.P2MessageReceiveV1) error {
	return func(_ context.Context, event *larkim.P2MessageReceiveV1) error {
		if event == nil || event.Event == nil || event.Event.Message == nil {
			return nil
		}

		messageID := valueOrEmpty(event.Event.Message.MessageId)
		chatID := valueOrEmpty(event.Event.Message.ChatId)
		chatType := valueOrEmpty(event.Event.Message.ChatType)
		senderOpenID := ""
		if event.Event.Sender != nil && event.Event.Sender.SenderId != nil && event.Event.Sender.SenderId.OpenId != nil {
			senderOpenID = *event.Event.Sender.SenderId.OpenId
		}
		log.Printf("received message event from feishu, message_id=%s chat_type=%s chat_id=%s sender_open_id=%s", messageID, chatType, chatID, senderOpenID)

		if dd.seenRecently(messageID) {
			log.Printf("skip duplicated event, message_id=%s", messageID)
			return nil
		}

		var raw []byte
		if event.EventReq != nil && len(event.EventReq.Body) > 0 {
			raw = event.EventReq.Body
		} else {
			fallback, err := buildFallbackPayload(event, cfg.verificationToken)
			if err != nil {
				return fmt.Errorf("build fallback payload: %w", err)
			}
			raw = fallback
		}

		normalized, err := normalizeWebhookPayload(raw, cfg.verificationToken)
		if err != nil {
			return err
		}

		reqCtx, cancel := context.WithTimeout(context.Background(), cfg.requestTimeout)
		defer cancel()

		if err := fw.postJSON(reqCtx, normalized); err != nil {
			return fmt.Errorf("forward to nullclaw failed: %w", err)
		}

		if strings.TrimSpace(chatID) == "" {
			chatID = "<empty>"
		}
		log.Printf("forwarded message event to nullclaw, message_id=%s chat_id=%s", messageID, chatID)
		return nil
	}
}

func main() {
	cfg, err := loadConfigFromEnv()
	if err != nil {
		log.Fatalf("invalid config: %v", err)
	}

	fw := &forwarder{
		client: &http.Client{},
		url:    cfg.nullclawWebhookURL,
	}
	dd := newDeduper(10 * time.Minute)

	eventHandler := dispatcher.NewEventDispatcher(cfg.verificationToken, cfg.encryptKey).
		OnP2MessageReceiveV1(messageHandler(cfg, fw, dd)).
		OnP2MessageReadV1(func(context.Context, *larkim.P2MessageReadV1) error {
			// Read receipts are expected and should not be forwarded to nullclaw.
			return nil
		})

	opts := []larkws.ClientOption{
		larkws.WithEventHandler(eventHandler),
		larkws.WithLogLevel(cfg.logLevel),
		larkws.WithAutoReconnect(true),
	}
	if cfg.useLarkSuite {
		opts = append(opts, larkws.WithDomain(lark.LarkBaseUrl))
	}

	wsClient := larkws.NewClient(cfg.appID, cfg.appSecret, opts...)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Printf("received shutdown signal, exiting")
		os.Exit(0)
	}()

	targetDomain := "feishu"
	if cfg.useLarkSuite {
		targetDomain = "larksuite"
	}
	log.Printf("bridge starting: ws_domain=%s webhook=%s", targetDomain, cfg.nullclawWebhookURL)

	if err := wsClient.Start(context.Background()); err != nil {
		log.Fatalf("bridge stopped with error: %v", err)
	}
}
