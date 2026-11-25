package main

import (
 "encoding/json"
 "net/http"
 "strings"
 "io"
 "testing"

 bolt "go.etcd.io/bbolt"
)

func TestUsageObserver(t *testing.T){
 for _,tc:=range []struct{name,kind,body string;clean,known bool}{
  {"json","application/json",`{"usage":{"input_tokens":3,"output_tokens":7,"total_tokens":10}}`,true,true},
  {"stream","text/event-stream","data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":3,\"output_tokens\":7,\"total_tokens\":10}}}\n\n",true,true},
  {"interrupted","application/json",`{"usage":{"input_tokens":3,"output_tokens":7,"total_tokens":10}}`,false,false},
  {"missing","application/json","{}",true,false},
  {"invalid totals","application/json",`{"usage":{"input_tokens":3,"output_tokens":7,"total_tokens":2}}`,true,false},
  {"negative","application/json",`{"usage":{"input_tokens":-3,"output_tokens":7,"total_tokens":4}}`,true,false},
  {"too large","application/json",strings.Repeat("a",maxUsageFrame+1),true,false},
 }{t.Run(tc.name,func(t *testing.T){
  o:=newUsageObserver(tc.kind)
  for i:=0;i<len(tc.body);i+=17{end:=i+17;if end>len(tc.body){end=len(tc.body)};o.feed([]byte(tc.body[i:end]))}
  u:=o.finish(tc.clean)
  if (u!=nil)!=tc.known{t.Fatalf("unexpected usage: %+v",u)}
  if u!=nil&&(u.Input!=3||u.Output!=7){t.Fatalf("unexpected totals: %+v",u)}
 })}
}
func TestReportedUsageAndAudit(t *testing.T){
 g,_,_:=fixture(t)
 g.client.Transport=transportFunc(func(*http.Request)(*http.Response,error){
  return &http.Response{StatusCode:200,Header:http.Header{"Content-Type":{"application/json"}},Body:io.NopCloser(strings.NewReader(`{"usage":{"input_tokens":3,"output_tokens":7,"total_tokens":10}}`))},nil
 })
 if w:=request(g,"POST","/v1/responses","inference",validBody);w.Code!=200{t.Fatal(w.Code)}
 w:=request(g,"GET","/usage","monitor","")
 var got struct{ReportedUsage usageTotals}
 if err:=json.Unmarshal(w.Body.Bytes(),&got);err!=nil||got.ReportedUsage.Known!=1||got.ReportedUsage.Input!=3||got.ReportedUsage.Output!=7{t.Fatalf("unexpected report: %s",w.Body.String())}
 if err:=g.db.View(func(tx *bolt.Tx)error{
  b:=tx.Bucket([]byte("audit"));if b==nil||b.Stats().KeyN!=2{t.Error("missing durable audit entries");return nil}
  return b.ForEach(func(_,v []byte)error{
   for _,secret:=range []string{"backend-secret","Bearer","hello"}{if strings.Contains(string(v),secret){t.Error("sensitive value in audit")}}
   return nil
  })
 });err!=nil{t.Fatal(err)}
}
func TestBackendDestination(t *testing.T){
 g,c,_:=fixture(t)
 g.backendMode="openai-api"
 c.Clients[0].MaxDailyInputBytes=100000
 c.Clients[0].MaxOutputTokens=100
 c.Clients[0].MaxDailyRequestedOutputTokens=1000
 writePolicy(t,g,c)
 g.client.Transport=transportFunc(func(r *http.Request)(*http.Response,error){
  if r.URL.String()!="https://api.openai.com/v1/responses"{t.Error("unexpected destination")}
  return &http.Response{StatusCode:200,Header:http.Header{},Body:io.NopCloser(strings.NewReader("{}"))},nil
 })
 if w:=request(g,"POST","/v1/responses","inference",validBody);w.Code!=200{t.Fatal(w.Code)}
}
