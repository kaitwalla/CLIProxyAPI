package config

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestT3IsolatedConfig(t *testing.T){
 t.Setenv("MANAGEMENT_PASSWORD","")
 makeConfig:=func()*Config{
  c:=&Config{Host:"127.0.0.1",Port:8317,AuthDir:t.TempDir(),MaxRetryCredentials:1}
  c.APIKeys=[]string{strings.Repeat("a",32)}
  c.KVStore.Disabled=true
  c.RemoteManagement.DisableControlPanel=true
  c.RemoteManagement.DisableAutoUpdatePanel=true
  c.Codex.DisableCodexCloaking=true
  c.CodexKey=[]CodexKey{{APIKey:strings.Repeat("b",32),BaseURL:"https://api.openai.com/v1",ProxyURL:"direct",Models:[]CodexModel{{Name:"gpt-example"}}}}
  return c
 }
 if e:=ValidateT3Isolated(makeConfig());e!=nil{t.Fatal(e)}
 for _,tc:=range []struct{name string;mutate func(*Config)}{
  {"public listener",func(c *Config){c.Host="0.0.0.0"}},
  {"plugins",func(c *Config){c.Plugins.Enabled=true}},
  {"management",func(c *Config){c.RemoteManagement.SecretKey="secret"}},
  {"home",func(c *Config){c.Home.Enabled=true}},
  {"alternate provider",func(c *Config){c.GeminiKey=[]GeminiKey{{}}}},
  {"second key",func(c *Config){c.CodexKey=append(c.CodexKey,c.CodexKey[0])}},
  {"subscription backend",func(c *Config){c.CodexKey[0].BaseURL="https://chatgpt.com/backend-api/codex"}},
  {"custom proxy",func(c *Config){c.CodexKey[0].ProxyURL="http://example.test"}},
  {"alias",func(c *Config){c.CodexKey[0].Models[0].Alias="other"}},
  {"retry",func(c *Config){c.RequestRetry=1}},
  {"bootstrap retry",func(c *Config){c.Streaming.BootstrapRetries=1}},
  {"quota fallback",func(c *Config){c.QuotaExceeded.SwitchProject=true}},
  {"payload override",func(c *Config){c.Payload.Override=[]PayloadRule{{}}}},
  {"credential file",func(c *Config){if e:=os.WriteFile(filepath.Join(c.AuthDir,"token.json"),[]byte("{}"),0600);e!=nil{t.Fatal(e)}}},
 }{t.Run(tc.name,func(t *testing.T){c:=makeConfig();tc.mutate(c);if ValidateT3Isolated(c)==nil{t.Fatal("unsafe configuration accepted")}})}
}

func TestT3IsolatedDeploymentTemplate(t *testing.T){
 t.Setenv("MANAGEMENT_PASSWORD","")
 raw,e:=os.ReadFile(filepath.Join("..","..","deploy","t3-gateway","cpa-isolated.example.yaml"));if e!=nil{t.Fatal(e)}
 dir:=t.TempDir()
 authDir:=filepath.Join(dir,"auth");if e=os.Mkdir(authDir,0700);e!=nil{t.Fatal(e)}
 path:=filepath.Join(dir,"config.yaml")
 body:=strings.ReplaceAll(string(raw),"/etc/t3-cpa/empty-auth",authDir)
 if e=os.WriteFile(path,[]byte(body),0600);e!=nil{t.Fatal(e)}
 cfg,e:=LoadConfigOptional(path,false);if e!=nil{t.Fatal(e)}
 if e=ValidateT3Isolated(cfg);e!=nil{t.Fatal(e)}
}
