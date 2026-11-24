package main

import (
 "bytes"
 "context"
 "encoding/json"
 "io"
 "net/http"
 "strings"
 "time"
)

func (g *gateway) backendReady(ctx context.Context)bool{
 ctx,cancel:=context.WithTimeout(ctx,3*time.Second);defer cancel()
 r,err:=http.NewRequestWithContext(ctx,http.MethodGet,"http://127.0.0.1:8317/t3-isolation",nil)
 if err!=nil{return false}
 r.Header.Set("Authorization","Bearer "+g.backendKey)
 resp,err:=g.client.Do(r)
 if err!=nil{return false}
 defer resp.Body.Close()
 return resp.StatusCode==http.StatusNoContent&&resp.Header.Get("X-CPA-T3-Isolated")=="api-key-v1"
}

// Reject duplicate fields including case variants at every object depth. Bound
// recursion independently of the standard JSON decoder's depth limit.
func uniqueJSON(b []byte) bool{
 d:=json.NewDecoder(bytes.NewReader(b));d.UseNumber()
 var walk func(int)bool
 walk=func(depth int)bool{
  if depth>128{return false}
  t,e:=d.Token();if e!=nil{return false}
  switch t{
  case json.Delim('{'):
   seen:=map[string]bool{}
   for d.More(){
    tok,e:=d.Token();key,ok:=tok.(string)
    if e!=nil||!ok{return false}
    key=strings.ToLower(key)
    if seen[key]{return false};seen[key]=true
    if !walk(depth+1){return false}
   }
   end,e:=d.Token();return e==nil&&end==json.Delim('}')
  case json.Delim('['):
   for d.More(){if !walk(depth+1){return false}}
   end,e:=d.Token();return e==nil&&end==json.Delim(']')
  default:return true
  }
 }
 if !walk(0){return false}
 _,err:=d.Token();return err==io.EOF
}

// Only stateless Responses requests with local client-side function tools are
// supported. This prevents hosted tools/background jobs spending beyond the
// request budget, and prevents clients accessing one another's stored state.
func restrictPayload(p map[string]json.RawMessage)bool{
 for k:=range p {
  switch strings.ToLower(k){
  case "previous_response_id","conversation","prompt","background","store","service_tier","tools":
   if k!=strings.ToLower(k){return false}
  }
 }
 for _,k:=range []string{"previous_response_id","conversation","prompt"}{
  if _,ok:=p[k];ok{return false}
 }
 for _,k:=range []string{"background","store"}{
  if raw,ok:=p[k];ok{
   var value bool
   if json.Unmarshal(raw,&value)!=nil||value{return false}
  }
  p[k]=json.RawMessage("false")
 }
 if raw,ok:=p["service_tier"];ok{
  var tier string
  if json.Unmarshal(raw,&tier)!=nil||(tier!="default"&&tier!="auto"){return false}
 }
 p["service_tier"]=json.RawMessage(`"default"`)
 if raw,ok:=p["tools"];ok{
  var tools []struct{Type string `json:"type"`}
  if json.Unmarshal(raw,&tools)!=nil{return false}
  for _,t:=range tools{if t.Type!="function"&&t.Type!="custom"{return false}}
 }
 // Reject server-side references and externally fetched media in the request's
 // input tree. Function arguments and text are opaque strings, not parsed JSON.
 if raw,ok:=p["input"];ok{
  var v any
  if json.Unmarshal(raw,&v)!=nil||!safeInput(v){return false}
 }
 return true
}
func safeInput(v any)bool{
 switch x:=v.(type){
 case []any:for _,item:=range x{if !safeInput(item){return false}}
 case map[string]any:
  if t,ok:=x["type"].(string);ok{
   switch t{case "item_reference","input_file","input_image","input_audio","computer_screenshot":return false}
  }
  for k,item:=range x{
   switch strings.ToLower(k){case "file_id","file_url","image_url","audio_url":return false}
   if !safeInput(item){return false}
  }
 }
 return true
}
