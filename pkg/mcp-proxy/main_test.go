package mcpproxy

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sigbit/mcp-auth-proxy/pkg/proxy"
	"github.com/stretchr/testify/require"
)

func TestRun_PassesHTTPStreamingOnlyToProxyRouter(t *testing.T) {
	originalNewProxyRouter := newProxyRouter
	t.Cleanup(func() {
		newProxyRouter = originalNewProxyRouter
	})

	var streamingOnlyReceived bool
	newProxyRouter = func(externalURL string, proxyHandler http.Handler, publicKey *rsa.PublicKey, proxyHeaders http.Header, httpStreamingOnly bool) (*proxy.ProxyRouter, error) {
		streamingOnlyReceived = httpStreamingOnly
		return nil, errors.New("proxy router init failed")
	}

	err := Run(
		":0",
		":0",
		false,
		"",
		"",
		false,
		"",
		"",
		t.TempDir(),
		"local",
		"",
		"http://localhost",
		"",
		"",
		nil,
		nil,
		"",
		"",
		nil,
		nil,
		"",
		"",
		"",
		nil,
		"",
		"",
		nil,
		nil,
		nil,
		nil,
		false,
		"",
		"",
		nil,
		nil,
		"",
		[]string{"http://example.com"},
		true,
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to create proxy router")
	require.True(t, streamingOnlyReceived, "httpStreamingOnly should be forwarded to proxy router")
}

func TestHealthzEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register healthz before auth middleware, same as in Run()
	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Add a catch-all that returns 401 to simulate auth middleware
	router.Use(func(c *gin.Context) {
		c.AbortWithStatus(http.StatusUnauthorized)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/healthz", nil)
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)
	require.Equal(t, "ok", body["status"])
}
