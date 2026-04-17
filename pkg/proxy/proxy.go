package proxy

import (
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mattn/go-jsonpointer"
)

type ProxyRouter struct {
	externalURL       string
	proxy             http.Handler
	publicKey         *rsa.PublicKey
	proxyHeaders      http.Header
	httpStreamingOnly bool
	headerMapping     map[string]string
	publicPaths       []string
}

func NewProxyRouter(
	externalURL string,
	proxy http.Handler,
	publicKey *rsa.PublicKey,
	proxyHeaders http.Header,
	httpStreamingOnly bool,
	headerMapping map[string]string,
	publicPaths []string,
) (*ProxyRouter, error) {
	return &ProxyRouter{
		externalURL:       externalURL,
		proxy:             proxy,
		publicKey:         publicKey,
		proxyHeaders:      proxyHeaders,
		httpStreamingOnly: httpStreamingOnly,
		headerMapping:     headerMapping,
		publicPaths:       publicPaths,
	}, nil
}

const (
	OauthProtectedResourceEndpoint = "/.well-known/oauth-protected-resource"
)

func (p *ProxyRouter) SetupRoutes(router gin.IRouter) {
	router.GET(OauthProtectedResourceEndpoint, p.handleProtectedResource)
	router.Use(p.handleProxy)
}

type protectedResourceResponse struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

func (p *ProxyRouter) handleProtectedResource(c *gin.Context) {
	c.JSON(http.StatusOK, protectedResourceResponse{
		Resource:             p.externalURL,
		AuthorizationServers: []string{p.externalURL},
	})
}

func (p *ProxyRouter) handleProxy(c *gin.Context) {
	// Allow configured public paths through without JWT authentication.
	for _, pp := range p.publicPaths {
		if strings.HasPrefix(c.Request.URL.Path, pp) {
			p.proxy.ServeHTTP(c.Writer, c.Request)
			c.Abort()
			return
		}
	}

	authHeader := c.Request.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	bearerToken := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(bearerToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return p.publicKey, nil
	})

	if err != nil || !token.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	if p.httpStreamingOnly && isSSEGetRequest(c.Request) {
		c.AbortWithStatusJSON(http.StatusMethodNotAllowed, gin.H{"error": "SSE (GET) streaming is not supported by this backend; use POST-based HTTP streaming instead"})
		return
	}

	c.Request.Header.Del("Authorization")
	for key, values := range p.proxyHeaders {
		for _, value := range values {
			c.Request.Header.Add(key, value)
		}
	}

	if len(p.headerMapping) > 0 {
		// Strip any client-supplied mapped headers to prevent forgery
		for _, headerName := range p.headerMapping {
			c.Request.Header.Del(headerName)
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			// DEBUG: log JWT claim keys and sub value
			claimKeys := make([]string, 0, len(claims))
			for k := range claims {
				claimKeys = append(claimKeys, k)
			}
			log.Printf("[proxy] DEBUG JWT claim keys: %v, sub=%v, userinfo exists=%v", claimKeys, claims["sub"], claims["userinfo"] != nil)

			// Try userinfo claim first, fall back to top-level claims
			var source any = claims
			if userinfo, exists := claims["userinfo"]; exists {
				source = userinfo
			}
			for pointer, headerName := range p.headerMapping {
				val, err := jsonpointer.Get(source, pointer)
				log.Printf("[proxy] DEBUG mapping %s -> %s: val=%v, err=%v", pointer, headerName, val, err)
				if err != nil {
					continue
				}
				switch v := val.(type) {
				case string:
					c.Request.Header.Set(headerName, v)
				case []any:
					var parts []string
					for _, item := range v {
						if s, ok := item.(string); ok {
							parts = append(parts, s)
						}
					}
					c.Request.Header.Set(headerName, strings.Join(parts, ","))
				default:
					c.Request.Header.Set(headerName, fmt.Sprintf("%v", v))
				}
			}
		}
	}

	p.proxy.ServeHTTP(c.Writer, c.Request)
}

func isSSEGetRequest(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	accept := r.Header.Get("Accept")
	if accept == "" {
		return false
	}
	for _, value := range strings.Split(accept, ",") {
		mediaType := strings.TrimSpace(strings.ToLower(value))
		if idx := strings.Index(mediaType, ";"); idx != -1 {
			mediaType = strings.TrimSpace(mediaType[:idx])
		}
		if mediaType == "text/event-stream" {
			return true
		}
	}
	return false
}
