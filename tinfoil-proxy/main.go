package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/tinfoilsh/tinfoil-go"
)

// Model configurations
var modelConfigs = map[string]struct {
	ModelID     string
	Description string
	Enclave     string
	Repo        string
}{
	"deepseek-r1-70b": {
		ModelID:     "deepseek-r1-70b",
		Description: "High-performance reasoning model",
		Enclave:     "deepseek-r1-70b-p.model.tinfoil.sh",
		Repo:        "tinfoilsh/confidential-deepseek-r1-70b-prod",
	},
	"llama3-3-70b": {
		ModelID:     "llama3-3-70b",
		Description: "Multilingual model optimized for dialogue",
		Enclave:     "llama3-3-70b.model.tinfoil.sh",
		Repo:        "tinfoilsh/confidential-llama3-3-70b",
	},
	"nomic-embed-text": {
		ModelID:     "nomic-embed-text",
		Description: "Text embedding model",
		Enclave:     "nomic-embed-text.model.tinfoil.sh",
		Repo:        "tinfoilsh/confidential-nomic-embed-text",
	},
}

// Request/Response models
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatCompletionRequest struct {
	Model             string           `json:"model"`
	Messages          []ChatMessage    `json:"messages"`
	Stream            *bool            `json:"stream,omitempty"`
	Temperature       *float32         `json:"temperature,omitempty"`
	MaxTokens         *int             `json:"max_tokens,omitempty"`
	TopP              *float32         `json:"top_p,omitempty"`
	FrequencyPenalty  *float32         `json:"frequency_penalty,omitempty"`
	PresencePenalty   *float32         `json:"presence_penalty,omitempty"`
	N                 *int             `json:"n,omitempty"`
	Stop              []string         `json:"stop,omitempty"`
	StreamOptions     *map[string]any  `json:"stream_options,omitempty"`
}

type ModelInfo struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

type ModelsResponse struct {
	Object string      `json:"object"`
	Data   []ModelInfo `json:"data"`
}

type Choice struct {
	Index        int         `json:"index"`
	Message      *ChatMessage `json:"message,omitempty"`
	Delta        *ChatMessage `json:"delta,omitempty"`
	FinishReason *string     `json:"finish_reason"`
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type ChatCompletionResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   *Usage   `json:"usage,omitempty"`
}

type TinfoilProxyServer struct {
	clients map[string]*tinfoil.Client
}

func NewTinfoilProxyServer() (*TinfoilProxyServer, error) {
	apiKey := os.Getenv("TINFOIL_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("TINFOIL_API_KEY environment variable is required")
	}

	server := &TinfoilProxyServer{
		clients: make(map[string]*tinfoil.Client),
	}

	// Temporarily only initialize deepseek model
	modelsToInit := []string{"deepseek-r1-70b"} // Comment out to load all: all keys from modelConfigs

	for _, modelName := range modelsToInit {
		config, ok := modelConfigs[modelName]
		if !ok {
			log.Printf("Model %s not found in modelConfigs", modelName)
			continue
		}

		log.Printf("Initializing %s", modelName)
		
		client, err := tinfoil.NewClientWithParams(
			config.Enclave,
			config.Repo,
			option.WithAPIKey(apiKey),
		)
		if err != nil {
			log.Printf("Failed to initialize model %s: %v", modelName, err)
			log.Printf("Skipping model %s due to initialization error", modelName)
			continue
		}
		
		server.clients[modelName] = client
		log.Printf("Successfully initialized Tinfoil client for model: %s", modelName)
	}

	if len(server.clients) == 0 {
		return nil, fmt.Errorf("no models could be initialized")
	}

	return server, nil
}

func (s *TinfoilProxyServer) getClient(model string) (*tinfoil.Client, error) {
	client, ok := s.clients[model]
	if !ok {
		return nil, fmt.Errorf("model '%s' not supported", model)
	}
	return client, nil
}

func (s *TinfoilProxyServer) streamChatCompletion(c *gin.Context, req ChatCompletionRequest) {
	client, err := s.getClient(req.Model)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Convert messages to OpenAI format
	messages := make([]openai.ChatCompletionMessageParamUnion, len(req.Messages))
	for i, msg := range req.Messages {
		switch msg.Role {
		case "user":
			messages[i] = openai.UserMessage(msg.Content)
		case "assistant":
			messages[i] = openai.AssistantMessage(msg.Content)
		case "system":
			messages[i] = openai.SystemMessage(msg.Content)
		default:
			messages[i] = openai.UserMessage(msg.Content)
		}
	}

	// Build chat completion params
	params := openai.ChatCompletionNewParams{
		Model:    req.Model,
		Messages: messages,
	}

	// Add optional parameters if provided
	if req.Temperature != nil {
		params.Temperature = openai.Float(float64(*req.Temperature))
	}
	if req.MaxTokens != nil {
		params.MaxTokens = openai.Int(int64(*req.MaxTokens))
	}
	if req.TopP != nil {
		params.TopP = openai.Float(float64(*req.TopP))
	}
	if req.FrequencyPenalty != nil {
		params.FrequencyPenalty = openai.Float(float64(*req.FrequencyPenalty))
	}
	if req.PresencePenalty != nil {
		params.PresencePenalty = openai.Float(float64(*req.PresencePenalty))
	}
	if req.N != nil {
		params.N = openai.Int(int64(*req.N))
	}
	// Note: Stop parameter handling is complex in the OpenAI Go SDK v1.3.0
	// For now, we'll skip this parameter
	if req.StreamOptions != nil {
		// Pass stream options to the params
		params.StreamOptions = openai.ChatCompletionStreamOptionsParam{
			IncludeUsage: openai.Bool((*req.StreamOptions)["include_usage"] == true),
		}
	}

	// Set up SSE headers
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	// Create context for cancellation
	ctx := c.Request.Context()

	// Start streaming
	stream := client.Chat.Completions.NewStreaming(ctx, params)
	defer stream.Close()
	
	// Stream responses
	w := c.Writer
	flusher, ok := w.(http.Flusher)
	if !ok {
		log.Printf("Response writer does not support flushing")
		return
	}

	for stream.Next() {
		chunk := stream.Current()
		
		// Convert to OpenAI-compatible format
		chunkData := ChatCompletionResponse{
			ID:      chunk.ID,
			Object:  "chat.completion.chunk",
			Created: chunk.Created,
			Model:   req.Model,
			Choices: make([]Choice, 0),
		}

		for _, choice := range chunk.Choices {
			choiceData := Choice{
				Index: int(choice.Index),
				Delta: &ChatMessage{},
			}
			
			if choice.Delta.Role != "" {
				choiceData.Delta.Role = string(choice.Delta.Role)
			}
			if choice.Delta.Content != "" {
				choiceData.Delta.Content = choice.Delta.Content
			}
			if choice.FinishReason != "" {
				finishReason := string(choice.FinishReason)
				choiceData.FinishReason = &finishReason
			}

			chunkData.Choices = append(chunkData.Choices, choiceData)
		}

		// Include usage data if available
		// Note: Usage is a struct, not a pointer in the OpenAI SDK
		if chunk.Usage.TotalTokens > 0 {
			chunkData.Usage = &Usage{
				PromptTokens:     int(chunk.Usage.PromptTokens),
				CompletionTokens: int(chunk.Usage.CompletionTokens),
				TotalTokens:      int(chunk.Usage.TotalTokens),
			}
		}

		data, err := json.Marshal(chunkData)
		if err != nil {
			log.Printf("Failed to marshal chunk data: %v", err)
			// Just terminate the stream cleanly without exposing the error
			fmt.Fprintf(w, "data: [DONE]\n\n")
			flusher.Flush()
			return
		}
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}

	if err := stream.Err(); err != nil {
		log.Printf("Stream error: %v", err)
		// Don't send error details to client since they can't handle it properly
	}

	fmt.Fprintf(w, "data: [DONE]\n\n")
	flusher.Flush()
}

func (s *TinfoilProxyServer) nonStreamingChatCompletion(c *gin.Context, req ChatCompletionRequest) {
	client, err := s.getClient(req.Model)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Convert messages to OpenAI format
	messages := make([]openai.ChatCompletionMessageParamUnion, len(req.Messages))
	for i, msg := range req.Messages {
		switch msg.Role {
		case "user":
			messages[i] = openai.UserMessage(msg.Content)
		case "assistant":
			messages[i] = openai.AssistantMessage(msg.Content)
		case "system":
			messages[i] = openai.SystemMessage(msg.Content)
		default:
			messages[i] = openai.UserMessage(msg.Content)
		}
	}

	// Build chat completion params
	params := openai.ChatCompletionNewParams{
		Model:    req.Model,
		Messages: messages,
	}

	// Add optional parameters if provided (same as streaming)
	if req.Temperature != nil {
		params.Temperature = openai.Float(float64(*req.Temperature))
	}
	if req.MaxTokens != nil {
		params.MaxTokens = openai.Int(int64(*req.MaxTokens))
	}
	if req.TopP != nil {
		params.TopP = openai.Float(float64(*req.TopP))
	}
	if req.FrequencyPenalty != nil {
		params.FrequencyPenalty = openai.Float(float64(*req.FrequencyPenalty))
	}
	if req.PresencePenalty != nil {
		params.PresencePenalty = openai.Float(float64(*req.PresencePenalty))
	}
	if req.N != nil {
		params.N = openai.Int(int64(*req.N))
	}

	// Create completion
	ctx := c.Request.Context()
	completion, err := client.Chat.Completions.New(ctx, params)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Convert to OpenAI-compatible format
	response := ChatCompletionResponse{
		ID:      completion.ID,
		Object:  "chat.completion",
		Created: completion.Created,
		Model:   req.Model,
		Choices: make([]Choice, 0),
	}

	for _, choice := range completion.Choices {
		finishReason := string(choice.FinishReason)
		choiceData := Choice{
			Index: int(choice.Index),
			Message: &ChatMessage{
				Role:    string(choice.Message.Role),
				Content: choice.Message.Content,
			},
			FinishReason: &finishReason,
		}
		response.Choices = append(response.Choices, choiceData)
	}

	// Include usage data
	// Note: Usage is a struct, not a pointer in the OpenAI SDK
	if completion.Usage.TotalTokens > 0 {
		response.Usage = &Usage{
			PromptTokens:     int(completion.Usage.PromptTokens),
			CompletionTokens: int(completion.Usage.CompletionTokens),
			TotalTokens:      int(completion.Usage.TotalTokens),
		}
	}

	c.JSON(http.StatusOK, response)
}

func main() {
	// Initialize proxy server
	server, err := NewTinfoilProxyServer()
	if err != nil {
		log.Fatalf("Failed to initialize proxy server: %v", err)
	}

	// Set up Gin router
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"service": "tinfoil-proxy",
		})
	})

	// List models endpoint
	r.GET("/v1/models", func(c *gin.Context) {
		models := []ModelInfo{}
		for modelID := range server.clients {
			models = append(models, ModelInfo{
				ID:      modelID,
				Object:  "model",
				Created: 1700000000,
				OwnedBy: "tinfoil",
			})
		}
		c.JSON(http.StatusOK, ModelsResponse{
			Object: "list",
			Data:   models,
		})
	})

	// Chat completions endpoint
	r.POST("/v1/chat/completions", func(c *gin.Context) {
		var req ChatCompletionRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		log.Printf("Chat completion request for model: %s, streaming: %v", req.Model, req.Stream != nil && *req.Stream)

		// Default to non-streaming if not specified
		isStreaming := req.Stream != nil && *req.Stream

		if isStreaming {
			server.streamChatCompletion(c, req)
		} else {
			server.nonStreamingChatCompletion(c, req)
		}
	})

	// Start server
	port := os.Getenv("TINFOIL_PROXY_PORT")
	if port == "" {
		port = "8093"
	}

	log.Printf("Tinfoil proxy server starting on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}