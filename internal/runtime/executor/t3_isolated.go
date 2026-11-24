package executor

import (
 "crypto/subtle"
 "encoding/json"
 "errors"

 "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
 cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// This check runs after translation, payload rewriting and session handling.
// Reject rather than silently forwarding when a downstream cap is lost.
func validateT3Outbound(cfg *config.Config,auth *cliproxyauth.Auth,key,baseURL string,original,final []byte) error {
 if !config.T3IsolatedMode(){return nil}
 if config.ValidateT3Isolated(cfg)!=nil||auth==nil||!codexAuthUsesAPIKey(auth)||baseURL!="https://api.openai.com/v1"||subtle.ConstantTimeCompare([]byte(key),[]byte(cfg.CodexKey[0].APIKey))!=1 {
  return errors.New("isolated CPA rejected upstream credential or destination")
 }
 return validateT3Wire(cfg,original,final)
}

func validateT3Wire(cfg *config.Config, original,final []byte) error {
 type tool struct{Type string `json:"type"`}
 type payload struct{
  Model string `json:"model"`
  MaxOutput int64 `json:"max_output_tokens"`
  Tools []tool `json:"tools"`
  Background bool `json:"background"`
  Store bool `json:"store"`
  ServiceTier string `json:"service_tier"`
 }
 var requested,wire payload
 if json.Unmarshal(original,&requested)!=nil||json.Unmarshal(final,&wire)!=nil||requested.MaxOutput<=0||wire.MaxOutput<=0||wire.MaxOutput>requested.MaxOutput||requested.Model!=wire.Model||wire.Background||wire.Store||(wire.ServiceTier!=""&&wire.ServiceTier!="default") {
  return errors.New("isolated CPA rejected modified or unbounded upstream payload")
 }
 found:=false
 for _,m:=range cfg.CodexKey[0].Models{if m.Name==wire.Model{found=true}}
 if !found{return errors.New("isolated CPA rejected upstream model")}
 for _,t:=range wire.Tools{if t.Type!="function"&&t.Type!="custom"{return errors.New("isolated CPA rejected hosted tool")}}
 return nil
}
