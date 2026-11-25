package config

import (
 "errors"
 "os"
 "strings"
)

// T3IsolatedMode is an operator-controlled process mode, not a request option.
// It is deliberately limited to a single official API-key credential; it does
// not authorize forwarding ChatGPT subscription tokens to other applications.
func T3IsolatedMode() bool { return os.Getenv("CPA_T3_ISOLATED") == "1" }

func ValidateT3Isolated(c *Config) error {
 if c==nil{return errors.New("isolated CPA configuration missing")}
 if c.Host!="127.0.0.1"||c.Port!=8317||c.Home.Enabled||c.Plugins.Enabled||c.Pprof.Enable||c.Discovery.Enabled||c.RemoteManagement.SecretKey!=""||c.RemoteManagement.AllowRemote||!c.RemoteManagement.DisableControlPanel||!c.RemoteManagement.DisableAutoUpdatePanel||os.Getenv("MANAGEMENT_PASSWORD")!=""||c.RequestLog||c.Debug||!c.KVStore.Disabled {
  return errors.New("isolated CPA requires private listener, no management, plugins, discovery, debug or local credential KV")
 }
 if len(c.APIKeys)!=1||len(strings.TrimSpace(c.APIKeys[0]))<32{return errors.New("isolated CPA requires one private gateway key")}
 if c.RequestRetry!=0||c.MaxRetryCredentials!=1||c.MaxRetryInterval!=0||c.Streaming.BootstrapRetries!=0||c.QuotaExceeded.SwitchProject||c.QuotaExceeded.SwitchPreviewModel||c.QuotaExceeded.AntigravityCredits||c.Codex.ResponseSteering||c.Codex.StreamBootstrapBuffering||c.Codex.UpstreamRequestCompression||c.Client.Codex.OptimizeMultiAgentV2 {
  return errors.New("isolated CPA forbids retry, fallback and alternate execution paths")
 }
 if len(c.GeminiKey)+len(c.InteractionsKey)+len(c.XAIKey)+len(c.MetaKey)+len(c.ClaudeKey)+len(c.OpenAICompatibility)+len(c.VertexCompatAPIKey)!=0||len(c.CodexKey)!=1||len(c.OAuthModelAlias)!=0||len(c.OAuthSettings)!=0||len(c.OAuthRequestScopedErrors)!=0||len(c.Payload.Default)+len(c.Payload.DefaultRaw)+len(c.Payload.Override)+len(c.Payload.OverrideRaw)+len(c.Payload.Replace)+len(c.Payload.Filter)!=0 {
  return errors.New("isolated CPA requires one Codex API key and no aliases or payload rules")
 }
 k:=c.CodexKey[0]
 if len(strings.TrimSpace(k.APIKey))<20||k.BaseURL!="https://api.openai.com/v1"||k.ProxyURL!="direct"||k.Prefix!=""||k.Websockets||k.AlphaSearch||len(k.Headers)!=0||len(k.Models)==0||len(k.RequestScopedErrors)!=0||(k.RequestRetry!=nil&&*k.RequestRetry>0)||!c.Codex.DisableCodexCloaking||(k.DisableCodexCloaking!=nil&&!*k.DisableCodexCloaking) {
  return errors.New("isolated CPA requires direct official OpenAI API credentials and no alternate routes")
 }
 for _,m:=range k.Models {
  if m.Name==""||strings.ContainsAny(m.Name,"/*() \t\r\n")||(m.Alias!=""&&m.Alias!=m.Name)||m.IsCompat||m.ForceMapping||m.SupportConfigurationUpdate{return errors.New("isolated CPA requires exact model names")}
 }
 // OAuth credential discovery must have no files to load. Use a separately
 // mounted, read-only empty directory, not the user's ordinary auth directory.
 if c.AuthDir==""{return errors.New("isolated CPA auth directory required")}
 entries,err:=os.ReadDir(c.AuthDir)
 if err!=nil||len(entries)!=0{return errors.New("isolated CPA auth directory must exist and be empty")}
 return nil
}
