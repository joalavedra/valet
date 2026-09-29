// Command demo is a mobile-first agent-commerce demo: a chat UI backed by
// Gemini, a tiny store, and Valet-mediated payments with phone approvals.
// It never handles card numbers — VGS reveals real values only to the store.
package main

import (
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed ui.html
var uiHTML []byte

type config struct {
	Listen      string
	PublicURL   string
	Password    string
	ValetURL    string
	AgentToken  string
	OwnerToken  string
	GeminiKey   string
	GeminiModel string
	CardLabel   string
}

type app struct {
	cfg     config
	store   *demoStore
	valet   *valetClient
	gemini  *geminiClient
	agent   *chatAgent
	mu      sync.Mutex
	orders  []order
	convs   map[string][]geminiContent
	pending map[string]string // conversation_id -> pending approval request id
}

func main() {
	cfg := config{
		Listen:      env("DEMO_LISTEN", ":8080"),
		PublicURL:   strings.TrimRight(os.Getenv("DEMO_PUBLIC_URL"), "/"),
		Password:    os.Getenv("DEMO_PASSWORD"),
		ValetURL:    strings.TrimRight(env("VALET_URL", "http://localhost:14400"), "/"),
		OwnerToken:  os.Getenv("VALET_OWNER_TOKEN"),
		GeminiKey:   os.Getenv("GEMINI_API_KEY"),
		GeminiModel: env("GEMINI_MODEL", "gemini-2.5-flash"),
		CardLabel:   env("DEMO_CARD_LABEL", "personal"),
	}
	cfg.AgentToken = os.Getenv("VALET_AGENT_TOKEN")
	if cfg.AgentToken == "" {
		if f := os.Getenv("VALET_AGENT_TOKEN_FILE"); f != "" {
			if b, err := os.ReadFile(f); err == nil {
				cfg.AgentToken = strings.TrimSpace(string(b))
			}
		}
	}
	a := &app{
		cfg:     cfg,
		store:   newDemoStore(),
		valet:   newValetClient(cfg.ValetURL, cfg.AgentToken, cfg.OwnerToken),
		convs:   map[string][]geminiContent{},
		pending: map[string]string{},
	}
	a.gemini = newGeminiClient(cfg.GeminiKey, cfg.GeminiModel)
	a.agent = newChatAgent(a)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /store/products", a.productsHandler)
	mux.HandleFunc("POST /store/checkout", a.checkoutHandler)
	mux.HandleFunc("GET /api/orders", a.ordersHandler)
	mux.HandleFunc("POST /api/chat", a.chatHandler)
	mux.HandleFunc("GET /api/state", a.stateHandler)
	mux.HandleFunc("POST /api/card/capture", a.captureHandler)
	mux.HandleFunc("POST /api/approvals/{id}/approve", a.decisionHandler("approve"))
	mux.HandleFunc("POST /api/approvals/{id}/deny", a.decisionHandler("deny"))
	mux.HandleFunc("POST /api/grants/{id}/revoke", a.revokeHandler)
	mux.HandleFunc("GET /manifest.webmanifest", a.manifestHandler)
	mux.HandleFunc("GET /{$}", a.indexHandler)
	// Unauthenticated reverse proxy for the Valet pages the phone needs:
	// /valet/capture/<token> (Collect.js) posts back into the same origin.
	mux.Handle("/valet/", http.StripPrefix("/valet",
		&valetProxy{target: cfg.ValetURL, client: &http.Client{Timeout: 30 * time.Second}}))

	handler := http.Handler(mux)
	if cfg.Password != "" {
		handler = basicAuth(handler, cfg.Password)
	}
	log.Printf("demo listening on %s (public %s)", cfg.Listen, cfg.PublicURL)
	log.Fatal(http.ListenAndServe(cfg.Listen, handler))
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// basicAuth gates everything except /store/*, /valet/* and the web manifest
// (VGS, the phone's capture page and Chrome's manifest fetch reach those
// without credentials).
func basicAuth(next http.Handler, password string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/store/") || strings.HasPrefix(r.URL.Path, "/valet/") ||
			r.URL.Path == "/manifest.webmanifest" {
			next.ServeHTTP(w, r)
			return
		}
		u, p, ok := r.BasicAuth()
		if !ok || u != "demo" || subtle.ConstantTimeCompare([]byte(p), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="valet-demo"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *app) indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(uiHTML)
}

func (a *app) manifestHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"name": "Valet Shop", "short_name": "Valet Shop",
		"start_url": "/", "display": "standalone",
		"background_color": "#0b0d10", "theme_color": "#0b0d10",
		"icons": []any{},
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
