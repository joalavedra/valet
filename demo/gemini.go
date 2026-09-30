package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Gemini REST shapes (v1beta generateContent, function calling).
type geminiPart struct {
	Text             string                  `json:"text,omitempty"`
	FunctionCall     *geminiFunctionCall     `json:"functionCall,omitempty"`
	FunctionResponse *geminiFunctionResponse `json:"functionResponse,omitempty"`
}

type geminiFunctionCall struct {
	Name string         `json:"name"`
	Args map[string]any `json:"args"`
}

type geminiFunctionResponse struct {
	Name     string         `json:"name"`
	Response map[string]any `json:"response"`
}

type geminiContent struct {
	Role  string       `json:"role"`
	Parts []geminiPart `json:"parts"`
}

type geminiToolDecl struct {
	FunctionDeclarations []geminiFuncDecl `json:"functionDeclarations"`
}

type geminiFuncDecl struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Parameters  any    `json:"parameters"`
}

type geminiRequest struct {
	SystemInstruction *geminiContent   `json:"system_instruction,omitempty"`
	Contents          []geminiContent  `json:"contents"`
	Tools             []geminiToolDecl `json:"tools,omitempty"`
}

type geminiResponse struct {
	Candidates []struct {
		Content geminiContent `json:"content"`
	} `json:"candidates"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type geminiClient struct {
	key   string
	model string
	http  *http.Client
}

func newGeminiClient(key, model string) *geminiClient {
	return &geminiClient{key: key, model: model, http: &http.Client{Timeout: 60 * time.Second}}
}

// generate posts one generateContent call and returns the model's content.
func (g *geminiClient) generate(ctx context.Context, req *geminiRequest) (*geminiContent, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent", g.model)
	hreq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("x-goog-api-key", g.key)
	resp, err := g.http.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var out geminiResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("gemini: bad response %d", resp.StatusCode)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("gemini: %s", out.Error.Message)
	}
	if len(out.Candidates) == 0 {
		return nil, fmt.Errorf("gemini: no candidates")
	}
	return &out.Candidates[0].Content, nil
}

var demoTools = []geminiToolDecl{{
	FunctionDeclarations: []geminiFuncDecl{
		{
			Name:        "list_products",
			Description: "List the products available in the Valet demo store.",
			Parameters:  map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			Name:        "checkout",
			Description: "Buy a product. Payment runs through Valet and needs the owner's approval on their phone; the call may take up to a few minutes while the owner decides.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"product_id": map[string]any{"type": "string", "description": "product id from list_products"},
					"qty":        map[string]any{"type": "integer", "description": "quantity, default 1"},
				},
				"required": []string{"product_id"},
			},
		},
		{
			Name: "buy_with_wallet",
			Description: "Pay a crypto-priced product (products with a rails field) from the user's Openfort wallet through Valet. " +
				"x402 settles USDC on Base Sepolia; mpp settles pathUSD on Tempo Moderato. Needs the owner's approval on their phone.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"product_id": map[string]any{"type": "string", "description": "product id from list_products"},
					"rail":       map[string]any{"type": "string", "enum": []string{"x402", "mpp"}, "description": "payment rail, default x402"},
				},
				"required": []string{"product_id"},
			},
		},
	},
}}
