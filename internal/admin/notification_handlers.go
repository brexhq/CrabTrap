package admin

import (
	"errors"
	"net/http"
	"strings"

	"github.com/brexhq/CrabTrap/internal/alerting"
)

// SetNotificationStore configures the alerting store used by notification channel endpoints.
func (a *API) SetNotificationStore(s alerting.Store) {
	a.notificationStore = s
}

// handleNotificationChannels handles GET (list) and POST (create) for /admin/notification-channels.
func (a *API) handleNotificationChannels(w http.ResponseWriter, r *http.Request) {
	callerID, callerRole, ok := a.requireRole(w, r, "manager")
	if !ok {
		return
	}
	if a.notificationStore == nil {
		http.Error(w, "Notification channels not available", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		var channels []alerting.NotificationChannel
		var err error
		if botID := r.URL.Query().Get("bot_id"); botID != "" {
			if callerRole != "admin" {
				if a.userStore == nil {
					http.Error(w, "User store not available", http.StatusServiceUnavailable)
					return
				}
				isMgr, mgrErr := a.userStore.IsManagerOf(callerID, botID)
				if mgrErr != nil || !isMgr {
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}
			channels, err = a.notificationStore.ListChannelsForBot(r.Context(), botID)
		} else if callerRole == "admin" {
			channels, err = a.notificationStore.ListChannelsForOwner(r.Context(), "")
		} else {
			channels, err = a.notificationStore.ListChannelsForOwner(r.Context(), callerID)
		}
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to list channels", err)
			return
		}
		respondJSON(w, http.StatusOK, channels)

	case http.MethodPost:
		limitBody(w, r, maxBodySize)
		var req struct {
			BotID       string `json:"bot_id"`
			ChannelType string `json:"channel_type"`
			Destination string `json:"destination"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		if req.ChannelType == "" || req.Destination == "" {
			http.Error(w, "channel_type and destination are required", http.StatusBadRequest)
			return
		}
		if !validChannelType(a, req.ChannelType) {
			http.Error(w, "unsupported channel_type: "+req.ChannelType, http.StatusBadRequest)
			return
		}
		if req.BotID != "" && callerRole != "admin" {
			if a.userStore == nil {
				http.Error(w, "User store not available", http.StatusServiceUnavailable)
				return
			}
			isMgr, err := a.userStore.IsManagerOf(callerID, req.BotID)
			if err != nil || !isMgr {
				http.Error(w, "Forbidden: you do not manage this bot", http.StatusForbidden)
				return
			}
		}
		ch := &alerting.NotificationChannel{
			OwnerID:     callerID,
			BotID:       req.BotID,
			ChannelType: req.ChannelType,
			Destination: req.Destination,
			Enabled:     true,
		}
		if err := a.notificationStore.CreateChannel(r.Context(), ch); err != nil {
			respondError(w, http.StatusInternalServerError, "failed to create channel", err)
			return
		}
		respondJSON(w, http.StatusCreated, ch)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleNotificationChannelAction handles /admin/notification-channels/{id} and /admin/notification-channels/{id}/test.
func (a *API) handleNotificationChannelAction(w http.ResponseWriter, r *http.Request) {
	callerID, callerRole, ok := a.requireRole(w, r, "manager")
	if !ok {
		return
	}
	if a.notificationStore == nil {
		http.Error(w, "Notification channels not available", http.StatusServiceUnavailable)
		return
	}

	const prefix = "/admin/notification-channels/"
	remaining := strings.TrimPrefix(r.URL.Path, prefix)
	if remaining == "" {
		http.NotFound(w, r)
		return
	}

	// Split: "notch_abc" or "notch_abc/test"
	parts := strings.SplitN(remaining, "/", 2)
	id := parts[0]
	subPath := ""
	if len(parts) > 1 {
		subPath = parts[1]
	}

	if id == "" {
		http.NotFound(w, r)
		return
	}
	if subPath != "" && subPath != "test" {
		http.NotFound(w, r)
		return
	}
	isTest := subPath == "test"

	ch, err := a.notificationStore.GetChannel(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusNotFound, "channel not found", err)
		return
	}

	// Auth: must be owner or admin
	if callerRole != "admin" && ch.OwnerID != callerID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if isTest {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if a.alertService == nil {
			http.Error(w, "Alerting service not available", http.StatusServiceUnavailable)
			return
		}
		msg := alerting.Message{
			BotID: "test-bot",
			Denials: []alerting.DenialInfo{
				{Method: "GET", URL: "https://api.example.com/test", Reason: "This is a test notification"},
			},
			Summary: "Test notification from CrabTrap. If you see this, your notification channel is working.",
		}
		sender := a.alertService.SenderFor(ch.ChannelType)
		if sender == nil {
			http.Error(w, "No sender configured for channel type: "+ch.ChannelType, http.StatusBadRequest)
			return
		}
		if err := sender.Send(r.Context(), ch.Destination, msg); err != nil {
			respondError(w, http.StatusBadGateway, "test send failed", err)
			return
		}
		respondJSON(w, http.StatusOK, map[string]string{"status": "sent"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		respondJSON(w, http.StatusOK, ch)

	case http.MethodPut:
		limitBody(w, r, maxBodySize)
		var req struct {
			ChannelType string `json:"channel_type"`
			Destination string `json:"destination"`
			Enabled     *bool  `json:"enabled"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		channelType := ch.ChannelType
		destination := ch.Destination
		enabled := ch.Enabled
		if req.ChannelType != "" {
			channelType = req.ChannelType
		}
		if req.Destination != "" {
			destination = req.Destination
		}
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		if !validChannelType(a, channelType) {
			http.Error(w, "unsupported channel_type: "+channelType, http.StatusBadRequest)
			return
		}
		if err := a.notificationStore.UpdateChannel(r.Context(), id, channelType, destination, enabled); err != nil {
			respondError(w, http.StatusInternalServerError, "failed to update channel", err)
			return
		}
		updated, err := a.notificationStore.GetChannel(r.Context(), id)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "updated but failed to read back", err)
			return
		}
		respondJSON(w, http.StatusOK, updated)

	case http.MethodDelete:
		if err := a.notificationStore.DeleteChannel(r.Context(), id); err != nil {
			if errors.Is(err, alerting.ErrNotFound) {
				respondError(w, http.StatusNotFound, "channel not found", err)
			} else {
				respondError(w, http.StatusInternalServerError, "failed to delete channel", err)
			}
			return
		}
		respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// validChannelType checks whether a channel_type is supported. If the alert
// service is wired, it checks registered senders. Otherwise falls back to a
// static allowlist so validation works even before the service is configured.
func validChannelType(a *API, channelType string) bool {
	if a.alertService != nil {
		return a.alertService.SenderFor(channelType) != nil
	}
	switch channelType {
	case "slack":
		return true
	default:
		return false
	}
}
