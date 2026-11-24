// t3-gateway is an opt-in, single-instance inference boundary.
package main

import (
 "bytes"
 "context"
 "crypto/sha256"
 "crypto/subtle"
 "encoding/hex"
 "encoding/json"
 "errors"
 "io"
 "log"
 "net/http"
 "os"
 "strings"
 "sync"
 "time"

 bolt "go.etcd.io/bbolt"
)

type policy struct {
 ID string
 KeyHash string
 MonitorHash string
 Models []string
 Expires time.Time
 RequestsPerDay int
 RequestsPerMinute int
 Concurrent int
 MaxBodyBytes int64
 MaxDailyInputBytes int64
 MaxOutputTokens int64
 MaxDailyRequestedOutputTokens int64
}
type config struct { Disabled bool; Clients []policy }
type counter struct { Day string; Daily int; Minute string; Recent int; InputBytes int64; RequestedOutputTokens int64 }
type gateway struct {
 configPath, backendKey string
 db *bolt.DB
 mu sync.Mutex
 active map[string]int
 client *http.Client
}
func matches(key, digest string) bool {
 expected, err := hex.DecodeString(digest)
 actual := sha256.Sum256([]byte(key))
 return key != "" && err == nil && subtle.ConstantTimeCompare(expected, actual[:]) == 1
}
func (g *gateway) load() (config,error) {
 var c config
 b,err:=os.ReadFile(g.configPath)
 if err!=nil{return c,err}
 d:=json.NewDecoder(bytes.NewReader(b)); d.DisallowUnknownFields()
 if err=d.Decode(&c);err!=nil{return c,err}
 if d.Decode(new(any))!=io.EOF{return c,errors.New("trailing config")}
 ids:=map[string]bool{}
 hashes:=map[string]bool{}
 for _,p:=range c.Clients {
  if p.ID==""||ids[p.ID]||p.Expires.IsZero()||p.RequestsPerDay<=0||p.RequestsPerMinute<=0||p.Concurrent<=0||p.MaxBodyBytes<=0||p.MaxBodyBytes>32<<20||p.MaxDailyInputBytes<0||p.MaxOutputTokens<0||p.MaxDailyRequestedOutputTokens<0||(p.MaxDailyRequestedOutputTokens>0&&p.MaxOutputTokens==0)||len(p.Models)==0{return c,errors.New("invalid client policy")}
  ids[p.ID]=true
  for _,h:=range []string{p.KeyHash,p.MonitorHash}{
   raw,e:=hex.DecodeString(h)
   if e!=nil||len(raw)!=32||hashes[strings.ToLower(h)]{return c,errors.New("invalid or duplicate key digest")}
   hashes[strings.ToLower(h)]=true
  }
 }
 return c,nil
}
func (g *gateway) admit(p policy, now time.Time, costs ...int64) error {
 var input,output int64
 if len(costs)==2 {input,output=costs[0],costs[1]}
 if input<0||output<0{return errors.New("invalid admission cost")}
 return g.db.Update(func(tx *bolt.Tx)error{
  b,err:=tx.CreateBucketIfNotExists([]byte("admission"));if err!=nil{return err}
  var v counter
  if raw:=b.Get([]byte(p.ID));raw!=nil {if err=json.Unmarshal(raw,&v);err!=nil{return err}}
  day:=now.UTC().Format("2006-01-02"); minute:=now.UTC().Format("2006-01-02T15:04")
  if v.Day!=day {v.Day=day;v.Daily=0;v.InputBytes=0;v.RequestedOutputTokens=0}
  if v.Minute!=minute{v.Minute=minute;v.Recent=0}
  if v.Daily>=p.RequestsPerDay||v.Recent>=p.RequestsPerMinute{return errQuota}
  if (p.MaxDailyInputBytes>0 && input>p.MaxDailyInputBytes-v.InputBytes)||(p.MaxDailyRequestedOutputTokens>0&&output>p.MaxDailyRequestedOutputTokens-v.RequestedOutputTokens){return errQuota}
  if input>int64(^uint64(0)>>1)-v.InputBytes||output>int64(^uint64(0)>>1)-v.RequestedOutputTokens{return errQuota}
  v.InputBytes+=input;v.RequestedOutputTokens+=output
  v.Daily++;v.Recent++
  raw,err:=json.Marshal(v);if err!=nil{return err}
  return b.Put([]byte(p.ID),raw)
 })
}
var errQuota=errors.New("quota exceeded")
func (g *gateway) ServeHTTP(w http.ResponseWriter,r *http.Request){
 w.Header().Set("Cache-Control","no-store")
 deny:=func(code int){http.Error(w,http.StatusText(code),code)}
 if r.URL.RawQuery!=""||r.URL.ForceQuery||r.URL.RawPath!=""||r.Header.Get("Upgrade")!=""{deny(403);return}
 inference:=r.Method=="POST"&&r.URL.Path=="/v1/responses"
 monitor:=r.Method=="GET"&&r.URL.Path=="/usage"
 if !inference&&!monitor{deny(404);return}
 a:=r.Header.Values("Authorization")
 if len(a)!=1||!strings.HasPrefix(a[0],"Bearer "){deny(401);return}
 key:=strings.TrimPrefix(a[0],"Bearer ")
 c,err:=g.load();if err!=nil||c.Disabled{deny(503);return}
 var p policy
 for _,v:=range c.Clients {
  digest:=v.KeyHash;if monitor{digest=v.MonitorHash}
  if matches(key,digest){p=v;break}
 }
 if p.ID==""||!time.Now().Before(p.Expires){deny(401);return}
 if monitor {
  var v counter
  err=g.db.View(func(tx *bolt.Tx)error{
   b:=tx.Bucket([]byte("admission"));if b==nil{return nil}
   raw:=b.Get([]byte(p.ID));if raw==nil{return nil};return json.Unmarshal(raw,&v)
  })
  if err!=nil{deny(503);return}
  w.Header().Set("Content-Type","application/json");_ = json.NewEncoder(w).Encode(v);return
 }
 body,err:=io.ReadAll(http.MaxBytesReader(w,r.Body,p.MaxBodyBytes));if err!=nil{deny(413);return}
 // Normalize the object before forwarding so downstream parsers cannot select
 // a different value from duplicate keys. Reject case variants of model.
 var payload map[string]json.RawMessage
 if json.Unmarshal(body,&payload)!=nil||payload==nil{deny(400);return}
 for k:=range payload {if strings.EqualFold(k,"model")&&k!="model"{deny(400);return}}
 var model string
 if json.Unmarshal(payload["model"],&model)!=nil{deny(400);return}
 allowed:=false
 for _,m:=range p.Models{if m==model{allowed=true}}
 if !allowed{deny(403);return}
 var output int64
 if p.MaxOutputTokens>0 {
  for k:=range payload{if strings.EqualFold(k,"max_output_tokens")&&k!="max_output_tokens"{deny(400);return}}
  output=p.MaxOutputTokens
  if raw,ok:=payload["max_output_tokens"];ok {
   if json.Unmarshal(raw,&output)!=nil||output<=0||output>p.MaxOutputTokens{deny(400);return}
  }
  payload["max_output_tokens"],_=json.Marshal(output)
 }
 body,err=json.Marshal(payload);if err!=nil{deny(400);return}
 g.mu.Lock()
 if g.active[p.ID]>=p.Concurrent{g.mu.Unlock();deny(429);return}
 err=g.admit(p,time.Now(),int64(len(body)),output)
 if err!=nil{g.mu.Unlock();if errors.Is(err,errQuota){deny(429)}else{deny(503)};return}
 g.active[p.ID]++
 g.mu.Unlock()
 defer func(){g.mu.Lock();g.active[p.ID]--;g.mu.Unlock()}()
 log.Printf("admitted client=%q model=%q",p.ID,model)
 ctx,cancel:=context.WithDeadline(r.Context(),p.Expires);defer cancel()
 // Revalidate independently of the client during an active stream. Policy
 // removal, expiry, key rotation or unreadable configuration cancels it.
 go g.watchPolicy(ctx,cancel,p,key,model)
 if !g.stillAllowed(p,key,model){deny(403);return}
 // The backend is deliberately fixed to the local CPA listener.
 req,err:=http.NewRequestWithContext(ctx,"POST","http://127.0.0.1:8317/v1/responses",bytes.NewReader(body))
 if err!=nil{deny(503);return}
 req.Header.Set("Authorization","Bearer "+g.backendKey)
 req.Header.Set("Content-Type","application/json")
 req.Header.Set("Accept","text/event-stream, application/json")
 resp,err:=g.client.Do(req)
 if err!=nil{log.Printf("upstream failed client=%q",p.ID);deny(502);return}
 defer resp.Body.Close()
 w.Header().Set("Content-Type",resp.Header.Get("Content-Type"))
 w.WriteHeader(resp.StatusCode)
 buf:=make([]byte,32<<10)
 for {n,e:=resp.Body.Read(buf);if n>0{if _,err=w.Write(buf[:n]);err!=nil{break};if f,ok:=w.(http.Flusher);ok{f.Flush()}};if e!=nil{break}}
 log.Printf("finished client=%q model=%q status=%d",p.ID,model,resp.StatusCode)
}
func (g *gateway) stillAllowed(original policy,key,model string) bool {
 c,err:=g.load()
 if err!=nil||c.Disabled{return false}
 for _,p:=range c.Clients {
  if p.ID!=original.ID||!matches(key,p.KeyHash)||!time.Now().Before(p.Expires){continue}
  for _,m:=range p.Models{if m==model{return true}}
 }
 return false
}
func (g *gateway) watchPolicy(ctx context.Context,cancel context.CancelFunc,p policy,key,model string){
 ticker:=time.NewTicker(250*time.Millisecond);defer ticker.Stop()
 for {
  select {
  case <-ctx.Done():return
  case <-ticker.C:
   if !g.stillAllowed(p,key,model){cancel();return}
  }
 }
}
func main(){
 path:=os.Getenv("T3_GATEWAY_CONFIG"); state:=os.Getenv("T3_GATEWAY_DB"); key:=os.Getenv("T3_GATEWAY_BACKEND_KEY")
 if path==""||state==""||key==""{log.Fatal("gateway configuration, database and backend key are required")}
 db,err:=bolt.Open(state,0600,&bolt.Options{Timeout:time.Second});if err!=nil{log.Fatal(err)};defer db.Close()
 g:=&gateway{configPath:path,backendKey:key,db:db,active:map[string]int{},client:&http.Client{Transport:&http.Transport{DisableKeepAlives:true},CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}}
 if _,err=g.load();err!=nil{log.Fatal(err)}
 s:=&http.Server{Addr:"127.0.0.1:8318",Handler:g,ReadHeaderTimeout:5*time.Second,ReadTimeout:30*time.Second,MaxHeaderBytes:16384}
 log.Fatal(s.ListenAndServe())
}
