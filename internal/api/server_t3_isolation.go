package api

import (
 "crypto/subtle"
 "net/http"

 "github.com/gin-gonic/gin"
 "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
 "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func (s *Server) t3IsolationMiddleware() gin.HandlerFunc {
 return func(c *gin.Context){
  cfg:=s.getConfig()
  if config.ValidateT3Isolated(cfg)!=nil {c.AbortWithStatus(http.StatusServiceUnavailable);return}
  r:=c.Request
  if r.URL.RawPath!=""||r.URL.RawQuery!=""||r.URL.ForceQuery||r.Header.Get("Upgrade")!=""{c.AbortWithStatus(http.StatusForbidden);return}
  readiness:=r.Method==http.MethodGet&&r.URL.Path=="/t3-isolation"
  inference:=r.Method==http.MethodPost&&r.URL.Path=="/v1/responses"
  if !readiness&&!inference{c.AbortWithStatus(http.StatusNotFound);return}
  a:=r.Header.Values("Authorization")
  if len(a)!=1||subtle.ConstantTimeCompare([]byte(a[0]),[]byte("Bearer "+cfg.APIKeys[0]))!=1{c.AbortWithStatus(http.StatusUnauthorized);return}
  if s.handlers==nil||s.handlers.AuthManager==nil{c.AbortWithStatus(http.StatusServiceUnavailable);return}
  entries:=s.handlers.AuthManager.List()
  if len(entries)!=1||entries[0]==nil||entries[0].Provider!="codex"||entries[0].AuthKind()!=auth.AuthKindAPIKey||subtle.ConstantTimeCompare([]byte(entries[0].Attributes["api_key"]),[]byte(cfg.CodexKey[0].APIKey))!=1{c.AbortWithStatus(http.StatusServiceUnavailable);return}
  c.Header("X-CPA-T3-Isolated","api-key-v1")
  if readiness{c.AbortWithStatus(http.StatusNoContent);return}
  c.Next()
 }
}
