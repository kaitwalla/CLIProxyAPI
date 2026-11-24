package main

import (
 "encoding/json"
 "io"
 "net/http"
 "net/http/httptest"
 "net/url"
 "strings"
 "sync/atomic"
 "testing"
)

func productionFixture(t *testing.T,mode string)(*gateway,config,*atomic.Int32){
 t.Helper()
 g,c,calls:=fixture(t)
 g.backendMode=mode
 p:=&c.Clients[0]
 p.MaxDailyInputBytes=100000;p.MaxOutputTokens=100;p.MaxDailyRequestedOutputTokens=1000
 writePolicy(t,g,c)
 return g,c,calls
}

func TestT3StrictPayload(t *testing.T){
 g,_,calls:=productionFixture(t,"openai-api")
 g.client.Transport=transportFunc(func(r *http.Request)(*http.Response,error){
  calls.Add(1)
  var p map[string]json.RawMessage
  if e:=json.NewDecoder(r.Body).Decode(&p);e!=nil{t.Error(e)}
  if string(p["store"])!="false"||string(p["background"])!="false"||string(p["service_tier"])!="\"default\""||string(p["max_output_tokens"])!="100"{t.Error("missing restrictions")}
  return &http.Response{StatusCode:200,Header:http.Header{},Body:io.NopCloser(strings.NewReader("{}"))},nil
 })
 for _,body:=range []string{
  `{"model":"allowed","previous_response_id":"resp_other"}`,
  `{"model":"allowed","conversation":"conv_other"}`,
  `{"model":"allowed","background":true}`,
  `{"model":"allowed","store":true}`,
  `{"model":"allowed","service_tier":"priority"}`,
  `{"model":"allowed","tools":[{"type":"web_search"}]}`,
  `{"model":"allowed","tools":[{"type":"mcp","server_url":"https://example.test"}]}`,
  `{"model":"allowed","input":[{"type":"item_reference","id":"item_other"}]}`,
  `{"model":"allowed","input":[{"type":"input_image","image_url":"https://example.test"}]}`,
 }{
  if w:=request(g,"POST","/v1/responses","inference",body);w.Code!=403{t.Errorf("unexpected status %d for %s",w.Code,body)}
 }
 for _,body:=range []string{
  `{"model":"allowed","model":"other"}`,
  `{"model":"allowed","input":[{"type":"message","Type":"item_reference"}]}`,
  `{"model":"allowed","max_output_tokens":15}`,
 }{
  if w:=request(g,"POST","/v1/responses","inference",body);w.Code!=400{t.Errorf("unexpected status %d for %s",w.Code,body)}
 }
 if w:=request(g,"POST","/v1/responses","inference",validBody);w.Code!=200{t.Fatal(w.Code)}
 if calls.Load()!=1{t.Fatal("denied requests reached provider")}
}
func TestT3CPAReadiness(t *testing.T){
 g,_,_:=productionFixture(t,"isolated-cpa")
 var inference atomic.Int32
 ready:=false
 g.client.Transport=transportFunc(func(r *http.Request)(*http.Response,error){
  h:=http.Header{};status:=200
  if r.URL.Path=="/t3-isolation" {
   if ready{h.Set("X-CPA-T3-Isolated","api-key-v1");status=204}
  }else{inference.Add(1);h.Set("X-CPA-T3-Isolated","api-key-v1")}
  return &http.Response{StatusCode:status,Header:h,Body:io.NopCloser(strings.NewReader(""))},nil
 })
 if w:=request(g,"POST","/v1/responses","inference",validBody);w.Code!=503||inference.Load()!=0{t.Fatal("unattested CPA reached inference")}
 ready=true
 if w:=request(g,"POST","/v1/responses","inference",validBody);w.Code!=200||inference.Load()!=1{t.Fatal("attested CPA failed")}
}
func TestT3UsageCutoff(t *testing.T){
 for _,strict:=range []bool{false,true}{t.Run(map[bool]string{true:"unknown",false:"reported"}[strict],func(t *testing.T){
  g,c,calls:=productionFixture(t,"openai-api")
  p:=&c.Clients[0];p.MaxDailyReportedTokens=10;p.Concurrent=1;p.RequireReportedUsage=strict
  writePolicy(t,g,c)
  g.client.Transport=transportFunc(func(*http.Request)(*http.Response,error){
   calls.Add(1);body:=`{"usage":{"input_tokens":3,"output_tokens":7,"total_tokens":10}}`
   if strict{body="{}"}
   return &http.Response{StatusCode:200,Header:http.Header{"Content-Type":{"application/json"}},Body:io.NopCloser(strings.NewReader(body))},nil
  })
  if w:=request(g,"POST","/v1/responses","inference",validBody);w.Code!=200{t.Fatal(w.Code)}
  if w:=request(g,"POST","/v1/responses","inference",validBody);w.Code!=429{t.Fatal("usage cutoff bypass")}
  if calls.Load()!=1{t.Fatal("unexpected provider calls")}
 })}
}
func TestT3HTTPStreamingEndToEnd(t *testing.T){
 g,_,_:=productionFixture(t,"openai-api")
 const frame="data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":3,\"output_tokens\":7,\"total_tokens\":10}}}\n\n"
 upstream:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.URL.Path!="/v1/responses"||r.Header.Get("Authorization")!="Bearer backend-secret"{t.Error("unexpected upstream request")}
  w.Header().Set("Content-Type","text/event-stream")
  _,_=io.WriteString(w,frame);w.(http.Flusher).Flush()
 }))
 defer upstream.Close()
 g.client.Transport=transportFunc(func(r *http.Request)(*http.Response,error){
  dest,_:=url.Parse(upstream.URL);dest.Path=r.URL.Path
  q:=r.Clone(r.Context());q.URL=dest;q.Host=dest.Host
  return http.DefaultTransport.RoundTrip(q)
 })
 edge:=httptest.NewServer(g);defer edge.Close()
 req,_:=http.NewRequest("POST",edge.URL+"/v1/responses",strings.NewReader(validBody));req.Header.Set("Authorization","Bearer inference")
 resp,e:=edge.Client().Do(req);if e!=nil{t.Fatal(e)}
 defer resp.Body.Close()
 body,e:=io.ReadAll(resp.Body);if e!=nil||resp.StatusCode!=200||string(body)!=frame{t.Fatalf("bad stream: %d %q %v",resp.StatusCode,body,e)}
}
