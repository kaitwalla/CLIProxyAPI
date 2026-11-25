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
 "sync/atomic"
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
 MaxDailyReportedTokens int64
 RequireReportedUsage bool
}
type config struct { Disabled bool; Clients []policy }
type counter struct { Day string; Daily int; Minute string; Recent int; InputBytes int64; RequestedOutputTokens int64 }
type gateway struct {
 configPath, backendKey string
 backendMode string
 db *bolt.DB
 mu sync.Mutex
 accountingFailed atomic.Bool
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
 if !uniqueJSON(b){return c,errors.New("ambiguous or invalid policy JSON")}
 if err=d.Decode(&c);err!=nil{return c,err}
 if d.Decode(new(any))!=io.EOF{return c,errors.New("trailing config")}
 ids:=map[string]bool{}
 hashes:=map[string]bool{}
 for _,p:=range c.Clients {
  if p.ID==""||strings.ContainsRune(p.ID,0)||ids[p.ID]||p.Expires.IsZero()||p.RequestsPerDay<=0||p.RequestsPerMinute<=0||p.Concurrent<=0||p.MaxBodyBytes<=0||p.MaxBodyBytes>32<<20||p.MaxDailyInputBytes<0||p.MaxOutputTokens<0||p.MaxDailyRequestedOutputTokens<0||p.MaxDailyReportedTokens<0||(p.MaxDailyRequestedOutputTokens>0&&p.MaxOutputTokens==0)||len(p.Models)==0{return c,errors.New("invalid client policy")}
  if g.backendMode!=""&&(p.MaxDailyInputBytes<=0||p.MaxOutputTokens<16||p.MaxDailyRequestedOutputTokens<=0){return c,errors.New("production policy requires positive input and output admission limits")}
  if p.RequireReportedUsage&&p.Concurrent!=1{return c,errors.New("strict usage reporting requires one concurrent request per client")}
  ids[p.ID]=true
  for _,h:=range []string{p.KeyHash,p.MonitorHash}{
   raw,e:=hex.DecodeString(h)
   if e!=nil||len(raw)!=32||hashes[strings.ToLower(h)]{return c,errors.New("invalid or duplicate key digest")}
   hashes[strings.ToLower(h)]=true
  }
 }
 return c,nil
}
func (g *gateway) admit(p policy, now time.Time, costs ...int64) error {return g.reserve(p,now,"",costs...)}
func (g *gateway) reserve(p policy, now time.Time, model string, costs ...int64) error {
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
  {
   var u usageTotals
   if ub:=tx.Bucket([]byte("reported-usage"));ub!=nil{if raw:=ub.Get([]byte(p.ID+"\x00"+day));raw!=nil{if err=json.Unmarshal(raw,&u);err!=nil{return err}}}
   if u.CapViolations>0{return errQuota}
   if p.RequireReportedUsage&&(u.Unknown>0||int64(v.Daily)!=u.Known+u.Unknown){return errQuota}
   if p.MaxDailyReportedTokens>0&&(u.Input>=p.MaxDailyReportedTokens||u.Output>=p.MaxDailyReportedTokens-u.Input){return errQuota}
  }
  if v.Daily>=p.RequestsPerDay||v.Recent>=p.RequestsPerMinute{return errQuota}
  if (p.MaxDailyInputBytes>0 && input>p.MaxDailyInputBytes-v.InputBytes)||(p.MaxDailyRequestedOutputTokens>0&&output>p.MaxDailyRequestedOutputTokens-v.RequestedOutputTokens){return errQuota}
  if input>int64(^uint64(0)>>1)-v.InputBytes||output>int64(^uint64(0)>>1)-v.RequestedOutputTokens{return errQuota}
  v.InputBytes+=input;v.RequestedOutputTokens+=output
  v.Daily++;v.Recent++
  raw,err:=json.Marshal(v);if err!=nil{return err}
  if err=b.Put([]byte(p.ID),raw);err!=nil{return err}
  return putAudit(tx,auditRecord{At:now.UTC(),Client:p.ID,Model:model,Event:"admitted",InputBytes:input,RequestedOutput:output})
 })
}
var errQuota=errors.New("quota exceeded")
func (g *gateway) ServeHTTP(w http.ResponseWriter,r *http.Request){
 w.Header().Set("Cache-Control","no-store")
 deny:=func(code int){http.Error(w,http.StatusText(code),code)}
 if r.URL.RawQuery!=""||r.URL.ForceQuery||r.URL.RawPath!=""||r.Header.Get("Upgrade")!=""{deny(403);return}
 inference:=r.Method=="POST"&&r.URL.Path=="/v1/responses"
 monitor:=r.Method=="GET"&&r.URL.Path=="/usage"
 discovery:=r.Method=="GET"&&r.URL.Path=="/v1/models"
 if !inference&&!monitor&&!discovery{deny(404);return}
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
 if discovery {
  models:=make([]map[string]string,0,len(p.Models))
  for _,m:=range p.Models{models=append(models,map[string]string{"id":m,"object":"model","owned_by":"restricted-gateway"})}
  w.Header().Set("Content-Type","application/json");_ = json.NewEncoder(w).Encode(map[string]any{"object":"list","data":models});return
 }
 if monitor {
  var v counter
  var usage usageTotals
  err=g.db.View(func(tx *bolt.Tx)error{
   if b:=tx.Bucket([]byte("reported-usage"));b!=nil{if raw:=b.Get([]byte(p.ID+"\x00"+time.Now().UTC().Format("2006-01-02")));raw!=nil{if e:=json.Unmarshal(raw,&usage);e!=nil{return e}}}
   b:=tx.Bucket([]byte("admission"));if b==nil{return nil}
   raw:=b.Get([]byte(p.ID));if raw==nil{return nil};return json.Unmarshal(raw,&v)
  })
  if err!=nil{deny(503);return}
  now:=time.Now().UTC();day:=now.Format("2006-01-02");minute:=now.Format("2006-01-02T15:04")
  if v.Day!=day{v=counter{Day:day,Minute:minute}}else if v.Minute!=minute{v.Minute=minute;v.Recent=0}
  w.Header().Set("Content-Type","application/json");_ = json.NewEncoder(w).Encode(struct{counter; ReportedUsage usageTotals}{v,usage});return
 }
 body,err:=io.ReadAll(http.MaxBytesReader(w,r.Body,p.MaxBodyBytes));if err!=nil{deny(413);return}
 // Normalize the object before forwarding so downstream parsers cannot select
 // a different value from duplicate keys. Reject case variants of model.
 var payload map[string]json.RawMessage
 if !uniqueJSON(body)||json.Unmarshal(body,&payload)!=nil||payload==nil{deny(400);return}
 for k:=range payload {if strings.EqualFold(k,"model")&&k!="model"{deny(400);return}}
 var model string
 if json.Unmarshal(payload["model"],&model)!=nil{deny(400);return}
 allowed:=false
 for _,m:=range p.Models{if m==model{allowed=true}}
 if !allowed{deny(403);return}
 if g.backendMode!=""&&!restrictPayload(payload){deny(403);return}
 var output int64
 if p.MaxOutputTokens>0 {
  for k:=range payload{if strings.EqualFold(k,"max_output_tokens")&&k!="max_output_tokens"{deny(400);return}}
  output=p.MaxOutputTokens
  if raw,ok:=payload["max_output_tokens"];ok {
   if json.Unmarshal(raw,&output)!=nil||output<=0||(g.backendMode!=""&&output<16)||output>p.MaxOutputTokens{deny(400);return}
  }
  payload["max_output_tokens"],_=json.Marshal(output)
 }
 body,err=json.Marshal(payload);if err!=nil{deny(400);return}
 g.mu.Lock()
 if g.accountingFailed.Load(){g.mu.Unlock();deny(503);return}
 if g.active[p.ID]>=p.Concurrent{g.mu.Unlock();deny(429);return}
 admitted:=time.Now()
 err=g.reserve(p,admitted,model,int64(len(body)),output)
 if err!=nil{g.mu.Unlock();if errors.Is(err,errQuota){deny(429)}else{deny(503)};return}
 g.active[p.ID]++
 g.mu.Unlock()
 defer func(){g.mu.Lock();g.active[p.ID]--;g.mu.Unlock()}()
 record:=auditRecord{Client:p.ID,Model:model,Event:"unknown",InputBytes:int64(len(body)),RequestedOutput:output}
 defer func(){record.At=time.Now().UTC();g.complete(record,admitted)}()
 deadline:=time.Now().Add(15*time.Minute);if p.Expires.Before(deadline){deadline=p.Expires}
 ctx,cancel:=context.WithDeadline(r.Context(),deadline);defer cancel()
 // Revalidate independently of the client during an active stream. Policy
 // removal, expiry, key rotation or unreadable configuration cancels it.
 go g.watchPolicy(ctx,cancel,p,key,model)
 if !g.stillAllowed(p,key,model){deny(403);return}
 if g.backendMode=="isolated-cpa"&&!g.backendReady(ctx){record.Event="backend_not_isolated";record.Status=503;deny(503);return}
 // Backend destinations are fixed, never supplied by the client.
 req,err:=http.NewRequestWithContext(ctx,"POST",g.backendURL(),bytes.NewReader(body))
 if err!=nil{deny(503);return}
 req.Header.Set("Authorization","Bearer "+g.backendKey)
 req.Header.Set("Content-Type","application/json")
 req.Header.Set("Accept","text/event-stream, application/json")
 resp,err:=g.client.Do(req)
 if err!=nil{record.Event="upstream_error";record.Status=502;deny(502);return}
 defer resp.Body.Close()
 if g.backendMode=="isolated-cpa"&&resp.Header.Get("X-CPA-T3-Isolated")!="api-key-v1"{record.Event="backend_not_isolated";record.Status=502;deny(502);return}
 record.Status=resp.StatusCode
 observer:=newUsageObserver(resp.Header.Get("Content-Type"))
 clean:=false
 w.Header().Set("Content-Type",resp.Header.Get("Content-Type"))
 w.WriteHeader(resp.StatusCode)
 buf:=make([]byte,32<<10)
 for {n,e:=resp.Body.Read(buf);if n>0{observer.feed(buf[:n]);_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(15*time.Second));if _,err=w.Write(buf[:n]);err!=nil{break};if f,ok:=w.(http.Flusher);ok{f.Flush()}};if e!=nil{clean=e==io.EOF;break}}
 if clean&&resp.StatusCode>=200&&resp.StatusCode<300{record.Usage=observer.finish(true)}
 if record.Usage!=nil{record.Event="reported_usage"}else{record.Event="usage_unknown"}
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
func (g *gateway) backendURL()string{
 if g.backendMode=="openai-api"{return "https://api.openai.com/v1/responses"}
 return "http://127.0.0.1:8317/v1/responses"
}
func main(){
 path:=os.Getenv("T3_GATEWAY_CONFIG"); state:=os.Getenv("T3_GATEWAY_DB"); key:=os.Getenv("T3_GATEWAY_BACKEND_KEY")
 if path==""||state==""||key==""{log.Fatal("gateway configuration, database and backend key are required")}
 mode:=os.Getenv("T3_GATEWAY_BACKEND_MODE")
 if mode!="openai-api"&&mode!="isolated-cpa"{log.Fatal("explicit backend mode required: openai-api or isolated-cpa")}
 db,err:=bolt.Open(state,0600,&bolt.Options{Timeout:time.Second});if err!=nil{log.Fatal(err)};defer db.Close()
 g:=&gateway{configPath:path,backendKey:key,backendMode:mode,db:db,active:map[string]int{},client:&http.Client{Timeout:15*time.Minute,Transport:&http.Transport{DisableKeepAlives:true,TLSHandshakeTimeout:10*time.Second,ResponseHeaderTimeout:2*time.Minute},CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}}
 if _,err=g.load();err!=nil{log.Fatal(err)}
 s:=&http.Server{Addr:"127.0.0.1:8318",Handler:g,ReadHeaderTimeout:5*time.Second,ReadTimeout:30*time.Second,IdleTimeout:30*time.Second,WriteTimeout:16*time.Minute,MaxHeaderBytes:16384}
 log.Fatal(s.ListenAndServe())
}
