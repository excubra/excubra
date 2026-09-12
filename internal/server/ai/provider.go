package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Request is one completion: a fixed system prompt and the situation as the user
// message. Response is the model's text and what it cost in tokens.
type Request struct {
	System    string
	User      string
	MaxTokens int
}

type Response struct {
	Text         string
	InputTokens  int
	OutputTokens int
}

// Provider is the exchangeable model backend (E21).
type Provider interface {
	Name() string
	Model() string
	Complete(ctx context.Context, req Request) (Response, error)
}

// Anthropic speaks the Messages API.
type Anthropic struct {
	URL   string
	Key   string
	Mdl   string
	HTTP  *http.Client
	Retry int
}

func (a *Anthropic) Name() string  { return "anthropic" }
func (a *Anthropic) Model() string { return a.Mdl }

func (a *Anthropic) Complete(ctx context.Context, req Request) (Response, error) {
	body := map[string]any{"model": a.Mdl, "max_tokens": req.MaxTokens, "system": req.System, "temperature": 0.2,
		"messages": []map[string]any{{"role": "user", "content": req.User}}}
	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Usage struct {
			In  int `json:"input_tokens"`
			Out int `json:"output_tokens"`
		} `json:"usage"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := post(ctx, a.HTTP, strings.TrimRight(a.URL, "/")+"/v1/messages", map[string]string{"x-api-key": a.Key, "anthropic-version": "2023-06-01"}, body, &out); err != nil {
		return Response{}, err
	}
	if out.Error != nil {
		return Response{}, errors.New(out.Error.Message)
	}
	var text strings.Builder
	for _, c := range out.Content {
		if c.Type == "text" {
			text.WriteString(c.Text)
		}
	}
	return Response{Text: text.String(), InputTokens: out.Usage.In, OutputTokens: out.Usage.Out}, nil
}

// OpenAI speaks the chat completions API, which Ollama, OpenAI and most others
// offer under /v1/chat/completions.
type OpenAI struct {
	URL  string
	Key  string
	Mdl  string
	HTTP *http.Client
}

func (o *OpenAI) Name() string  { return "openai" }
func (o *OpenAI) Model() string { return o.Mdl }

func (o *OpenAI) Complete(ctx context.Context, req Request) (Response, error) {
	body := map[string]any{"model": o.Mdl, "max_tokens": req.MaxTokens, "temperature": 0.2,
		"messages": []map[string]any{{"role": "system", "content": req.System}, {"role": "user", "content": req.User}}}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			In  int `json:"prompt_tokens"`
			Out int `json:"completion_tokens"`
		} `json:"usage"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	headers := map[string]string{}
	if o.Key != "" {
		headers["Authorization"] = "Bearer " + o.Key
	}
	if err := post(ctx, o.HTTP, strings.TrimRight(o.URL, "/")+"/v1/chat/completions", headers, body, &out); err != nil {
		return Response{}, err
	}
	if out.Error != nil {
		return Response{}, errors.New(out.Error.Message)
	}
	if len(out.Choices) == 0 {
		return Response{}, errors.New("empty answer")
	}
	return Response{Text: out.Choices[0].Message.Content, InputTokens: out.Usage.In, OutputTokens: out.Usage.Out}, nil
}

func post(ctx context.Context, hc *http.Client, url string, headers map[string]string, body any, out any) error {
	if hc == nil {
		hc = &http.Client{Timeout: 3 * time.Minute}
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return err
	}
	if res.StatusCode/100 != 2 {
		msg := strings.TrimSpace(string(data))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Errorf("HTTP %d: %s", res.StatusCode, msg)
	}
	return json.Unmarshal(data, out)
}
