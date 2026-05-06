package notifications

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// SSEClient represents a connected SSE client.
type SSEClient struct {
	id            string
	userID        string
	messages      chan []byte
	done          chan struct{}
	allowedBotIDs map[string]bool // if non-nil, only receive events for these user IDs
}

// SSEChannel implements the Channel interface for Server-Sent Events.
// At most one active connection is tracked per userID.
type SSEChannel struct {
	name    string
	clients map[string]*SSEClient // userID → connection
	mu      sync.RWMutex
}

// NewSSEChannel creates a new SSE channel.
func NewSSEChannel(name string) *SSEChannel {
	return &SSEChannel{
		name:    name,
		clients: make(map[string]*SSEClient),
	}
}

// Name returns the channel identifier.
func (s *SSEChannel) Name() string {
	return s.name
}

// Notify delivers event to the appropriate SSE clients.
// If event.TargetUserID is set, only that user's connection receives it.
// Otherwise the event is fanned out to all connected clients, respecting
// per-client allowedBotIDs filters.
func (s *SSEChannel) Notify(event Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	message := formatSSEMessage(string(event.Type), data)

	s.mu.RLock()
	defer s.mu.RUnlock()

	if event.TargetUserID != "" {
		if client, ok := s.clients[event.TargetUserID]; ok {
			s.deliver(client, message)
		}
	} else {
		sourceUserID := eventSourceUserID(event)
		for _, client := range s.clients {
			if client.allowedBotIDs != nil {
				if sourceUserID == "" || !client.allowedBotIDs[sourceUserID] {
					continue
				}
			}
			s.deliver(client, message)
		}
	}

	return nil
}

func (s *SSEChannel) deliver(client *SSEClient, message []byte) {
	select {
	case client.messages <- message:
	case <-client.done:
		// Client disconnected, skip
	default:
		slog.Warn("SSE client buffer full, dropping message", "client_id", client.id)
	}
}

// ServeHTTPForUser handles an SSE connection for an authenticated user.
// If the user already has a connection, it is replaced by the new one.
// userID must be non-empty; call sites are responsible for enforcing auth.
func (s *SSEChannel) ServeHTTPForUser(w http.ResponseWriter, r *http.Request, userID string) {
	s.ServeHTTPForUserScoped(w, r, userID, nil)
}

func (s *SSEChannel) setClient(client *SSEClient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.clients[client.userID]; ok {
		close(old.messages)
	}
	s.clients[client.userID] = client
}

func (s *SSEChannel) removeClient(client *SSEClient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.clients[client.userID]; ok && current.id == client.id {
		close(client.messages)
		delete(s.clients, client.userID)
	}
}

// ClientCount returns the number of connected clients.
func (s *SSEChannel) ClientCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.clients)
}

func formatSSEMessage(eventType string, data []byte) []byte {
	return []byte(fmt.Sprintf("event: %s\ndata: %s\n\n", eventType, data))
}

// eventSourceUserID extracts the originating bot/user ID from an event's payload.
func eventSourceUserID(event Event) string {
	if event.Data == nil {
		return ""
	}
	type hasUserID interface {
		GetUserID() string
	}
	if src, ok := event.Data.(hasUserID); ok {
		return src.GetUserID()
	}
	return ""
}

// ServeHTTPForUserScoped handles an SSE connection that only receives events
// for the specified set of bot user IDs. Pass nil for allowedBotIDs to receive all events.
func (s *SSEChannel) ServeHTTPForUserScoped(w http.ResponseWriter, r *http.Request, userID string, allowedBotIDs []string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	var rndBuf [8]byte
	_, _ = rand.Read(rndBuf[:])
	clientID := fmt.Sprintf("%s-%d-%s", r.RemoteAddr, time.Now().UnixNano(), hex.EncodeToString(rndBuf[:]))
	client := &SSEClient{
		id:       clientID,
		userID:   userID,
		messages: make(chan []byte, 100),
		done:     make(chan struct{}),
	}
	if allowedBotIDs != nil {
		client.allowedBotIDs = make(map[string]bool, len(allowedBotIDs))
		for _, id := range allowedBotIDs {
			client.allowedBotIDs[id] = true
		}
	}

	s.setClient(client)
	defer s.removeClient(client)

	slog.Debug("SSE client connected", "client_id", clientID, "user_id", userID, "scoped", allowedBotIDs != nil)

	fmt.Fprintf(w, "data: {\"type\":\"connected\",\"client_id\":\"%s\"}\n\n", clientID)
	flusher.Flush()

	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			close(client.done)
			slog.Debug("SSE client disconnected", "client_id", clientID)
			return

		case message, ok := <-client.messages:
			if !ok {
				close(client.done)
				slog.Debug("SSE client messages channel closed, stopping", "client_id", clientID)
				return
			}
			if _, err := w.Write(message); err != nil {
				slog.Error("error writing to SSE client", "client_id", clientID, "error", err)
				close(client.done)
				return
			}
			flusher.Flush()

		case <-heartbeat.C:
			fmt.Fprintf(w, ":heartbeat\n\n")
			flusher.Flush()
		}
	}
}
