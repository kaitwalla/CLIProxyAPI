package main

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strings"
 "sync"
 "sync/atomic"
 "testing"
 "time"

 bolt "go.etcd.io/bbolt"
)

type transportFunc func(*http.Request)(*http.Response,error)
func (f transportFunc) RoundTrip(r *http.Request)(*http.Response,error){return f(r)}
func digest(s string)string{v:=sha256.Sum256([]byte(s));return hex.EncodeToString(v[:])}
const validBody = `{"model":"allowed","input":"hello"}`
func writePolicy(t *testing.T,g *gateway,c config){
 t.Helper()
 b,e:=json.Marshal(c);if e!=nil{t.Fatal(e)}
 if e=os.WriteFile(g.configPath,b,0600);e!=nil{t.Fatal(e)}
}
func fixture(t *testing.T)(*gateway,config,*atomic.Int32){
 t.Helper()
 dir:=t.TempDir()
 db,e:=bolt.Open(filepath.Join(dir,"state.db"),0600,nil);if e!=nil{t.Fatal(e)}
 g:=&gateway{configPath:filepath.Join(dir,"policy.json"),backendKey:"backend-secret",db:db,active:map[string]int{}}
 t.Cleanup(func(){_ = g.db.Close()})
 calls:=new(atomic.Int32)
 g.client=&http.Client{Transport:transportFunc(func(r *http.Request)(*http.Response,error){
  calls.Add(1)
  if r.URL.String()!="http://127.0.0.1:8317/v1/responses"||r.Method!="POST"{t.Error("unexpected upstream route")}
  if r.Header.Get("Authorization")!="Bearer backend-secret"{t.Error("incorrect backend credential")}
  if r.Header.Get("X-Api-Key")!=""||r.Header.Get("X-Forwarded-For")!=""{t.Error("untrusted headers forwarded")}
  return &http.Response{StatusCode:200,Header:http.Header{"Content-Type":{"text/event-stream"}},Body:io.NopCloser(strings.NewReader("data: done\n\n"))},nil
 })}
 c:=config{Clients:[]policy{{ID:"desktop",KeyHash:digest("inference"),MonitorHash:digest("monitor"),Models:[]string{"allowed"},Expires:time.Now().Add(time.Hour),RequestsPerDay:20,RequestsPerMinute:20,Concurrent:2,MaxBodyBytes:1024}}}
 writePolicy(t,g,c)
 return g,c,calls
}
func request(g *gateway,method,path,key,body string)*httptest.ResponseRecorder{
 r:=httptest.NewRequest(method,path,strings.NewReader(body))
 if key!=""{r.Header.Set("Authorization","Bearer "+key)}
 w:=httptest.NewRecorder();g.ServeHTTP(w,r);return w
}
func TestDeniedRequestsNeverReachBackend(t *testing.T){
 g,_,calls:=fixture(t)
 cases:=[]struct{name,method,path,key,body string;status int}{
  {"missing key","POST","/v1/responses","",validBody,401},
  {"unknown key","POST","/v1/responses","bad",validBody,401},
  {"monitor cannot infer","POST","/v1/responses","monitor",validBody,401},
  {"inference cannot monitor","GET","/usage","inference","",401},
  {"management","GET","/v0/management/auth-files","inference","",404},
  {"management v8","GET","/v8/management/config","inference","",404},
  {"tunnel","GET","/v1/tunnel","inference","",404},
  {"websocket route","GET","/v1/responses","inference","",404},
  {"alternate alias","POST","/backend-api/codex/responses","inference",validBody,404},
  {"compact","POST","/v1/responses/compact","inference",validBody,404},
  {"query","POST","/v1/responses?key=x","inference",validBody,403},
  {"encoded path","POST","/v1/%72esponses","inference",validBody,403},
  {"disallowed model","POST","/v1/responses","inference",`{"model":"other"}`,403},
  {"case variant","POST","/v1/responses","inference",`{"model":"allowed","Model":"other"}`,400},
  {"missing model","POST","/v1/responses","inference",`{}`,400},
  {"invalid JSON","POST","/v1/responses","inference","{",400},
  {"oversized","POST","/v1/responses","inference",strings.Repeat("x",1025),413},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
  if w:=request(g,tc.method,tc.path,tc.key,tc.body);w.Code!=tc.status{t.Errorf("status=%d want %d",w.Code,tc.status)}
 })}
 for _,header:=range []string{"Authorization","Upgrade"}{
  r:=httptest.NewRequest("POST","/v1/responses",strings.NewReader(validBody));r.Header.Set("Authorization","Bearer inference")
  if header=="Authorization"{r.Header.Add(header,"Bearer monitor")}else{r.Header.Set(header,"websocket")}
  w:=httptest.NewRecorder();g.ServeHTTP(w,r);if w.Code<400{t.Errorf("accepted %s",header)}
 }
 if calls.Load()!=0{t.Fatal("denied requests reached backend")}
}
func TestForwardingAndMonitoring(t *testing.T){
 g,_,calls:=fixture(t)
 r:=httptest.NewRequest("POST","/v1/responses",strings.NewReader(validBody))
 r.Header.Set("Authorization","Bearer inference");r.Header.Set("X-Api-Key","evil");r.Header.Set("X-Forwarded-For","evil")
 w:=httptest.NewRecorder();g.ServeHTTP(w,r)
 if w.Code!=200||w.Body.String()!="data: done\n\n"||!w.Flushed{t.Fatal("stream not forwarded")}
 m:=request(g,"GET","/usage","monitor","")
 var v counter
 if m.Code!=200||json.Unmarshal(m.Body.Bytes(),&v)!=nil||v.Daily!=1||v.Recent!=1{t.Fatal("unexpected monitoring response")}
 if calls.Load()!=1{t.Fatal("unexpected upstream calls")}
}
func TestPolicyChangesFailClosed(t *testing.T){
 g,c,calls:=fixture(t)
 original:=c.Clients[0]
 c.Disabled=true;writePolicy(t,g,c)
 if w:=request(g,"POST","/v1/responses","inference",validBody);w.Code!=503{t.Fatal("kill switch ignored")}
 c.Disabled=false;c.Clients[0].Expires=time.Now().Add(-time.Hour);writePolicy(t,g,c)
 if w:=request(g,"POST","/v1/responses","inference",validBody);w.Code!=401{t.Fatal("expiry ignored")}
 c.Clients=nil;writePolicy(t,g,c)
 if w:=request(g,"POST","/v1/responses","inference",validBody);w.Code!=401{t.Fatal("revocation ignored")}
 c.Clients=[]policy{original,original};writePolicy(t,g,c)
 if w:=request(g,"POST","/v1/responses","inference",validBody);w.Code!=503{t.Fatal("invalid policy accepted")}
 if e:=os.Remove(g.configPath);e!=nil{t.Fatal(e)}
 if w:=request(g,"POST","/v1/responses","inference",validBody);w.Code!=503{t.Fatal("missing policy accepted")}
 if calls.Load()!=0{t.Fatal("denied requests reached backend")}
}
func TestDurableQuota(t *testing.T){
 g,c,calls:=fixture(t)
 c.Clients[0].RequestsPerDay=1;writePolicy(t,g,c)
 if w:=request(g,"POST","/v1/responses","inference",validBody);w.Code!=200{t.Fatal(w.Code)}
 path:=g.db.Path();if e:=g.db.Close();e!=nil{t.Fatal(e)}
 db,e:=bolt.Open(path,0600,nil);if e!=nil{t.Fatal(e)};g.db=db
 if w:=request(g,"POST","/v1/responses","inference",validBody);w.Code!=429{t.Fatal("budget reset")}
 if calls.Load()!=1{t.Fatal("quota bypass")}
}
func TestAtomicAdmissionAndWindowRollover(t *testing.T){
 g,c,_:=fixture(t);p:=c.Clients[0];p.RequestsPerMinute=3;p.RequestsPerDay=4
 now:=time.Date(2026,11,23,12,0,0,0,time.UTC)
 var wg sync.WaitGroup;var successes atomic.Int32
 for i:=0;i<32;i++{wg.Add(1);go func(){defer wg.Done();e:=g.admit(p,now);if e==nil{successes.Add(1)}else if !errors.Is(e,errQuota){t.Error(e)}}()}
 wg.Wait();if successes.Load()!=3{t.Fatalf("admitted %d",successes.Load())}
 if e:=g.admit(p,now.Add(time.Minute));e!=nil{t.Fatal(e)}
 if e:=g.admit(p,now.Add(2*time.Minute));!errors.Is(e,errQuota){t.Fatal("daily limit bypass")}
 if e:=g.admit(p,now.Add(24*time.Hour));e!=nil{t.Fatal(e)}
}
func TestConcurrencyAndUpstreamFailure(t *testing.T){
 g,c,_:=fixture(t);c.Clients[0].Concurrent=1;writePolicy(t,g,c)
 entered:=make(chan struct{});release:=make(chan struct{})
 g.client.Transport=transportFunc(func(*http.Request)(*http.Response,error){close(entered);<-release;return nil,fmt.Errorf("offline")})
 done:=make(chan int,1);go func(){done<-request(g,"POST","/v1/responses","inference",validBody).Code}()
 select{case <-entered:case <-time.After(5*time.Second):close(release);t.Fatal("upstream not reached")}
 if w:=request(g,"POST","/v1/responses","inference",validBody);w.Code!=429{t.Error("concurrency bypass")}
 close(release);if status:=<-done;status!=502{t.Errorf("status=%d",status)}
 if g.active["desktop"]!=0{t.Fatal("slot leaked")}
 m:=request(g,"GET","/usage","monitor","");var v counter
 if json.Unmarshal(m.Body.Bytes(),&v)!=nil||v.Daily!=1{t.Fatal("failed upstream attempt not charged")}
}
func TestStorageFailureDeniesInference(t *testing.T){
 g,_,calls:=fixture(t)
 if e:=g.db.Close();e!=nil{t.Fatal(e)}
 if w:=request(g,"POST","/v1/responses","inference",validBody);w.Code!=503{t.Fatal("storage failure did not fail closed")}
 if calls.Load()!=0{t.Fatal("storage failure reached upstream")}
}

func TestActiveRevocation(t *testing.T) {
 for _,mode:=range []string{"disabled","removed","rotated","model","expired","invalid"} {
  t.Run(mode,func(t *testing.T){
   g,c,_:=fixture(t)
   entered:=make(chan struct{})
   cancelled:=make(chan struct{})
   g.client.Transport=transportFunc(func(r *http.Request)(*http.Response,error){
    close(entered)
    <-r.Context().Done()
    close(cancelled)
    return nil,r.Context().Err()
   })
   done:=make(chan int,1)
   go func(){done<-request(g,"POST","/v1/responses","inference",validBody).Code}()
   select{case <-entered:case <-time.After(5*time.Second):t.Fatal("upstream not reached")}
   switch mode {
   case "disabled":c.Disabled=true
   case "removed":c.Clients=nil
   case "rotated":c.Clients[0].KeyHash=digest("rotated")
   case "model":c.Clients[0].Models=[]string{"other"}
   case "expired":c.Clients[0].Expires=time.Now().Add(-time.Second)
   case "invalid":c.Clients[0].Concurrent=0
   }
   writePolicy(t,g,c)
   select{case <-cancelled:case <-time.After(3*time.Second):t.Fatal("upstream context not cancelled")}
   select{case status:=<-done:if status!=502{t.Errorf("status=%d",status)};case <-time.After(3*time.Second):t.Fatal("handler did not finish")}
   if g.active["desktop"]!=0{t.Fatal("concurrency slot leaked")}
  })
 }
}

func TestRequestedOutputBudget(t *testing.T){
 g,c,calls:=fixture(t)
 c.Clients[0].MaxOutputTokens=100
 c.Clients[0].MaxDailyRequestedOutputTokens=150
 writePolicy(t,g,c)
 g.client.Transport=transportFunc(func(r *http.Request)(*http.Response,error){
  calls.Add(1)
  var body map[string]json.RawMessage
  if err:=json.NewDecoder(r.Body).Decode(&body);err!=nil{t.Error(err)}
  var n int
  if err:=json.Unmarshal(body["max_output_tokens"],&n);err!=nil||n!=100{t.Errorf("output cap not injected: %d",n)}
  return &http.Response{StatusCode:200,Header:http.Header{},Body:io.NopCloser(strings.NewReader("{}"))},nil
 })
 for _,b:=range []string{`{"model":"allowed","max_output_tokens":101}`,`{"model":"allowed","max_output_tokens":-1}`,`{"model":"allowed","Max_Output_Tokens":1000}`,`{"model":"allowed","max_output_tokens":1.5}`}{
  if w:=request(g,"POST","/v1/responses","inference",b);w.Code!=400{t.Errorf("invalid output limit accepted: %s",b)}
 }
 if w:=request(g,"POST","/v1/responses","inference",validBody);w.Code!=200{t.Fatal(w.Code)}
 if w:=request(g,"POST","/v1/responses","inference",validBody);w.Code!=429{t.Fatal("daily output budget bypass")}
 if calls.Load()!=1{t.Fatal("unexpected upstream calls")}
}
func TestInputBudgetAndAtomicReservation(t *testing.T){
 g,c,_:=fixture(t);p:=c.Clients[0]
 p.MaxDailyInputBytes=100;p.MaxDailyRequestedOutputTokens=100;p.MaxOutputTokens=50
 now:=time.Now()
 var wg sync.WaitGroup;var successes atomic.Int32
 for i:=0;i<32;i++{wg.Add(1);go func(){defer wg.Done();e:=g.admit(p,now,40,40);if e==nil{successes.Add(1)}else if !errors.Is(e,errQuota){t.Error(e)}}()}
 wg.Wait();if successes.Load()!=2{t.Fatalf("admitted %d",successes.Load())}
 if e:=g.admit(p,now,21,1);!errors.Is(e,errQuota){t.Fatal("input budget bypass")}
 if e:=g.admit(p,now,1,21);!errors.Is(e,errQuota){t.Fatal("output budget bypass")}
 if e:=g.admit(p,now.Add(24*time.Hour),100,100);e!=nil{t.Fatal(e)}
}
