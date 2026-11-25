package main

import (
 "bytes"
 "encoding/json"
 "io"
 "log"
 "mime"
 "time"

 bolt "go.etcd.io/bbolt"
)

const maxUsageFrame = 2 << 20

type reportedUsage struct {
 Input int64 `json:"input_tokens"`
 Output int64 `json:"output_tokens"`
 Total int64 `json:"total_tokens"`
}
type usageObserver struct {
 streaming bool
 invalid bool
 pending []byte
 result *reportedUsage
}
func newUsageObserver(contentType string)*usageObserver{
 kind,_,_:=mime.ParseMediaType(contentType)
 return &usageObserver{streaming:kind=="text/event-stream",invalid:kind!="text/event-stream"&&kind!="application/json"}
}
func (o *usageObserver) parse(raw []byte){
 var envelope struct{
  Type string `json:"type"`
  Usage *reportedUsage `json:"usage"`
  Response *struct{Usage *reportedUsage `json:"usage"`} `json:"response"`
 }
 if json.Unmarshal(raw,&envelope)!=nil{return}
 u:=envelope.Usage
 if o.streaming {
  if envelope.Type!="response.completed"&&envelope.Type!="response.incomplete"{return}
  if envelope.Response==nil{return}
  u=envelope.Response.Usage
 }
 if u==nil||u.Input<0||u.Output<0||u.Total<=0||u.Input>u.Total||u.Output!=u.Total-u.Input{return}
 if o.result!=nil {o.invalid=true;return}
 o.result=u
}
func (o *usageObserver) feed(b []byte){
 if o.invalid{return}
 if !o.streaming {
  if len(b)>maxUsageFrame-len(o.pending){o.invalid=true;o.pending=nil;return}
  o.pending=append(o.pending,b...);return
 }
 for len(b)>0 {
  i:=bytes.IndexByte(b,'\n')
  n:=len(b);if i>=0{n=i+1}
  if n>maxUsageFrame-len(o.pending){o.invalid=true;o.pending=nil;return}
  o.pending=append(o.pending,b[:n]...);b=b[n:]
  if i>=0{
   line:=bytes.TrimRight(o.pending,"\r\n")
   if bytes.HasPrefix(line,[]byte("data:")){o.parse(bytes.TrimSpace(line[5:]))}
   o.pending=o.pending[:0]
  }
 }
}
func (o *usageObserver) finish(clean bool)*reportedUsage{
 if o.invalid||!clean{return nil}
 if !o.streaming{o.parse(o.pending)}
 if o.invalid{return nil}
 return o.result
}

type auditRecord struct{
 At time.Time `json:"at"`
 Client string `json:"client"`
 Model string `json:"model"`
 Event string `json:"event"`
 Status int `json:"status,omitempty"`
 InputBytes int64 `json:"input_bytes,omitempty"`
 RequestedOutput int64 `json:"requested_output,omitempty"`
 Usage *reportedUsage `json:"reported_usage,omitempty"`
}
func putAudit(tx *bolt.Tx,a auditRecord)error{
 b,e:=tx.CreateBucketIfNotExists([]byte("audit"));if e!=nil{return e}
 seq,e:=b.NextSequence();if e!=nil{return e}
 var k [8]byte
 for i:=7;i>=0;i--{k[i]=byte(seq);seq>>=8}
 raw,e:=json.Marshal(a);if e!=nil{return e}
 return b.Put(k[:],raw)
}
func (g *gateway) complete(a auditRecord,admitted time.Time){
 e:=g.db.Update(func(tx *bolt.Tx)error{
  if a.Usage!=nil&&a.RequestedOutput>0&&a.Usage.Output>a.RequestedOutput{a.Event="output_cap_violation"}
  if e:=putAudit(tx,a);e!=nil{return e}
  b,e:=tx.CreateBucketIfNotExists([]byte("reported-usage"));if e!=nil{return e}
  key:=[]byte(a.Client+"\x00"+admitted.UTC().Format("2006-01-02"))
  var v usageTotals
  if raw:=b.Get(key);raw!=nil{if e=json.Unmarshal(raw,&v);e!=nil{return e}}
  if a.Event=="output_cap_violation"{v.CapViolations++}
  if a.Usage==nil{v.Unknown++}else{
   max:=int64(^uint64(0)>>1)
   if a.Usage.Input>max-v.Input||a.Usage.Output>max-v.Output{return io.ErrShortBuffer}
   v.Input+=a.Usage.Input;v.Output+=a.Usage.Output;v.Known++
  }
  raw,e:=json.Marshal(v);if e!=nil{return e};return b.Put(key,raw)
 })
 if e!=nil{g.accountingFailed.Store(true);log.Print("gateway completion accounting failed; admissions suspended")}
}
type usageTotals struct{Input int64;Output int64;Known int64;Unknown int64;CapViolations int64}
