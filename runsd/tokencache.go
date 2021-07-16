package main

import (
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"k8s.io/klog/v2"
)

var (
	tokenCache = &cache{nodes: make(map[string]cacheNode)}
	parser     = &jwt.Parser{}
)

func getToken(audience string) string {
	if val, ok := tokenCache.get(audience); ok && !val.IsExpired() {
		klog.V(6).Infof("cache hit audience '%s'", audience)
		return val.token
	}

	klog.V(5).Infof("cache miss audience '%s'", audience)
	return ""
}

func setToken(audience, token string) {
	claims := jwt.StandardClaims{}
	_, _, err := parser.ParseUnverified(token, &claims)
	if err != nil || claims.ExpiresAt == 0 {
		klog.V(3).Infof("cache invalid token %v", err)
		return
	}

	expiry := time.Unix(claims.ExpiresAt, 0).Add(-time.Minute)

	klog.V(5).Infof("cache set '%v' expires '%s'", audience, expiry.String())
	tokenCache.set(audience, cacheNode{
		token:  token,
		expiry: expiry,
	})
}

type cache struct {
	nodes map[string]cacheNode
	mutex sync.RWMutex
}

func (c *cache) set(k string, v cacheNode) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.nodes[k] = v
}

func (c *cache) get(k string) (cacheNode, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	v, ok := c.nodes[k]

	return v, ok
}

type cacheNode struct {
	token  string
	expiry time.Time
}

func (c cacheNode) IsExpired() bool {
	return time.Now().After(c.expiry)
}
