package executor

import (
 "testing"
 "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestT3FinalWireBudget(t *testing.T){
 c:=&config.Config{CodexKey:[]config.CodexKey{{Models:[]config.CodexModel{{Name:"allowed"}}}}}
 original:=[]byte(`{"model":"allowed","max_output_tokens":100}`)
 if err:=validateT3Wire(c,original,original);err!=nil{t.Fatal(err)}
 for _,wire:=range []string{
  `{"model":"allowed"}`,
  `{"model":"allowed","max_output_tokens":101}`,
  `{"model":"other","max_output_tokens":100}`,
  `{"model":"allowed","max_output_tokens":100,"background":true}`,
  `{"model":"allowed","max_output_tokens":100,"store":true}`,
  `{"model":"allowed","max_output_tokens":100,"service_tier":"priority"}`,
  `{"model":"allowed","max_output_tokens":100,"tools":[{"type":"web_search"}]}`,
 }{if err:=validateT3Wire(c,original,[]byte(wire));err==nil{t.Errorf("unsafe wire payload accepted: %s",wire)}}
 t.Setenv("CPA_T3_ISOLATED","1")
 if err:=validateT3Outbound(c,nil,"","https://chatgpt.com/backend-api/codex",original,original);err==nil{t.Fatal("invalid credential accepted")}
}
