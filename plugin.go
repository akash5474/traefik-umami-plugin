// Package plugindemo a demo plugin.
package traefik_umami_plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config the plugin configuration.
type Config struct {
	ForwardPath            string   `json:"forwardPath"`
	UmamiHost              string   `json:"umamiHost"`
	WebsiteId              string   `json:"websiteId"`
	AutoTrack              bool     `json:"autoTrack"`
	DoNotTrack             bool     `json:"doNotTrack"`
	Cache                  bool     `json:"cache"`
	Domains                []string `json:"domains"`
	EvadeGoogleTagManager  bool     `json:"evadeGoogleTagManager"`
	ScriptInjection        bool     `json:"scriptInjection"`
	ScriptInjectionMode    string   `json:"scriptInjectionMode"`
	ServerSideTracking     bool     `json:"serverSideTracking"`
	ServerSideTrackingMode string   `json:"serverSideTrackingMode"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		ForwardPath:            "_umami",
		UmamiHost:              "",
		WebsiteId:              "",
		AutoTrack:              true,
		DoNotTrack:             false,
		Cache:                  false,
		Domains:                []string{},
		EvadeGoogleTagManager:  false,
		ScriptInjection:        true,
		ScriptInjectionMode:    SIModeTag,
		ServerSideTracking:     false,
		ServerSideTrackingMode: SSTModeAll,
	}
}

const (
	SIModeTag          string = "tag"
	SIModeSource       string = "source"
	SSTModeAll         string = "all"
	SSTModeNotinjected string = "notinjected"
)

// PluginHandler a PluginHandler plugin.
type PluginHandler struct {
	next          http.Handler
	name          string
	config        Config
	configIsValid bool
	scriptHtml    string
	LogHandler    *log.Logger
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// construct
	h := &PluginHandler{
		next:          next,
		name:          name,
		config:        *config,
		configIsValid: true,
		scriptHtml:    "",
		LogHandler:    log.New(os.Stdout, "", 0),
	}

	// check if the umami host is set
	if config.UmamiHost == "" {
		h.log("umamiHost is not set!")
		h.configIsValid = false
	}
	// check if the website id is set
	if config.WebsiteId == "" {
		h.log("websiteId is not set!")
		h.configIsValid = false
	}
	// check if scriptInjectionMode is valid
	if config.ScriptInjectionMode != SIModeTag && config.ScriptInjectionMode != SIModeSource {
		h.log("scriptInjectionMode is not valid!")
		h.config.ScriptInjection = false
		h.configIsValid = false
	}
	// check if serverSideTrackingMode is valid
	if config.ServerSideTrackingMode != SSTModeAll && config.ServerSideTrackingMode != SSTModeNotinjected {
		h.log("serverSideTrackingMode is not valid!")
		h.config.ServerSideTracking = false
		h.configIsValid = false
	}

	// build script html
	scriptHtml, err := buildUmamiScript(&h.config)
	h.scriptHtml = scriptHtml
	if err != nil {
		return nil, err
	}

	configJSON, _ := json.Marshal(config)
	h.log(fmt.Sprintf("config: %s", configJSON))
	if config.ScriptInjection {
		h.log(fmt.Sprintf("script: %s", scriptHtml))
	} else {
		h.log("script: scriptInjection is false")
	}

	return h, nil
}

func (h *PluginHandler) log(message string) {
	level := "info" // default to info
	time := time.Now().Format("2006-01-02T15:04:05Z")

	if h.LogHandler != nil {
		h.LogHandler.Println(fmt.Sprintf("time=\"%s\" level=%s msg=\"[traefik-umami-plugin] %s\"", time, level, message))
	}
}

func (h *PluginHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// check if config is valid
	if !h.configIsValid {
		h.next.ServeHTTP(rw, req)
		return
	}

	// forwarding
	shouldForwardToUmami, pathAfter := isUmamiForwardPath(req, &h.config)
	if shouldForwardToUmami {
		// h.log(fmt.Sprintf("Forward %s", req.URL.EscapedPath()))
		h.forwardToUmami(rw, req, pathAfter)
		return
	}

	// script injection
	var injected bool = false
	if h.config.ScriptInjection {
		// intercept body
		myrw := &responseWriter{
			buffer:         &bytes.Buffer{},
			ResponseWriter: rw,
		}
		myrw.Header().Set("Accept-Encoding", "identity")
		h.next.ServeHTTP(myrw, req)

		if strings.HasPrefix(myrw.Header().Get("Content-Type"), "text/html") {
			h.log(fmt.Sprintf("Processing HTML response for injection on path: %s", req.URL.EscapedPath()))
			
			origBytes := myrw.buffer.Bytes()
			origLength := len(origBytes)
			h.log(fmt.Sprintf("Original content length: %d", origLength))
			
			// Get original Content-Length header if it exists
			origContentLength := myrw.Header().Get("Content-Length")
			h.log(fmt.Sprintf("Original Content-Length header: %s", origContentLength))
			
			newBytes := regexReplaceSingle(origBytes, insertBeforeRegex, h.scriptHtml)
			newLength := len(newBytes)
			
			if !bytes.Equal(origBytes, newBytes) {
				h.log(fmt.Sprintf("Script injected successfully. New content length: %d (delta: +%d)", newLength, newLength-origLength))
				
				// Update Content-Length header to match new content size
				rw.Header().Set("Content-Length", strconv.Itoa(newLength))
				h.log(fmt.Sprintf("Updated Content-Length header to: %d", newLength))
				
				// Copy other headers from the intercepted response
				for key, values := range myrw.Header() {
					if key != "Content-Length" {
						for _, value := range values {
							rw.Header().Add(key, value)
						}
					}
				}
				
				_, err := rw.Write(newBytes)
				if err != nil {
					h.log(fmt.Sprintf("Error writing modified response: %s", err.Error()))
				} else {
					h.log("Modified response written successfully")
				}
				injected = true
			} else {
				h.log("No injection performed - content unchanged")
			}
		} else {
			contentType := myrw.Header().Get("Content-Type")
			h.log(fmt.Sprintf("Skipping injection - not HTML content. Content-Type: %s", contentType))
		}
	}

	// server side tracking
	shouldServerSideTrack := shouldServerSideTrack(req, &h.config, injected, h)
	if shouldServerSideTrack {
		// h.log(fmt.Sprintf("Track %s", req.URL.EscapedPath()))
		go buildAndSendTrackingRequest(req, &h.config)
	}

	if !injected {
		h.log(fmt.Sprintf("Passing through original response for path: %s", req.URL.EscapedPath()))
		h.next.ServeHTTP(rw, req)
	}
}

type responseWriter struct {
	buffer *bytes.Buffer
	http.ResponseWriter
}

func (w *responseWriter) Write(p []byte) (int, error) {
	return w.buffer.Write(p)
}
