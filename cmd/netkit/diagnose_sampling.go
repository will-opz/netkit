package main

import (
 "context"
 "math"
 "sort"
 "time"
)

const maxPinnedRepeat=10

// BackendSampling is additive evidence. The original backends report keeps
// exactly one probe per IP and retains its existing JSON contract.
type BackendSampling struct {
 Requested int `json:"requested"`
 TotalPlanned int `json:"total_planned"`
 TotalCompleted int `json:"total_completed"`
 Incomplete bool `json:"incomplete,omitempty"`
 Nodes []BackendSampleStatistics `json:"nodes"`
}
type BackendSampleStatistics struct {
 ID string `json:"id"`
 IP string `json:"ip"`
 Planned int `json:"planned"`
 Completed int `json:"completed"`
 HTTP2xx int `json:"http_2xx"`
 Redirects int `json:"redirects"`
 Restricted int `json:"restricted"`
 Errors int `json:"errors"`
 MinMS *int64 `json:"min_ms,omitempty"`
 MedianMS *int64 `json:"median_ms,omitempty"`
 P95MS *int64 `json:"p95_ms,omitempty"`
 MaxMS *int64 `json:"max_ms,omitempty"`
 HTTPStatuses map[string]int `json:"http_statuses"`
 Protocols map[string]int `json:"protocols"`
 ALPN map[string]int `json:"alpn"`
 Samples []BackendSample `json:"samples"`
}
type BackendSample struct {
 Index int `json:"index"`
 Status string `json:"status"`
 DurationMS int64 `json:"duration_ms"`
 HTTPStatusCode int `json:"http_status_code,omitempty"`
 HTTPProtocol string `json:"http_protocol,omitempty"`
 TLSALPN string `json:"tls_alpn,omitempty"`
 ErrorCode string `json:"error_code,omitempty"`
}

type PinnedSampleFn func(context.Context,DiagnosticPlan,string)PinnedBackendProbe

func sampleDurationPercentiles(values []int64)(min,median,p95,max *int64){
 if len(values)==0{return nil,nil,nil,nil}
 sorted:=append([]int64(nil),values...)
 sort.Slice(sorted,func(i,j int)bool{return sorted[i]<sorted[j]})
 a,b,c,d:=sorted[0],sorted[(len(sorted)-1)/2],sorted[int(math.Ceil(float64(len(sorted))*0.95))-1],sorted[len(sorted)-1]
 if len(sorted)%2==0{b=(sorted[len(sorted)/2-1]+sorted[len(sorted)/2])/2}
 return &a,&b,&c,&d
}
func buildSampleStats(base PinnedBackendProbe,requested int)BackendSampleStatistics{
 return BackendSampleStatistics{
  ID:base.ID,IP:base.IP,Planned:requested,
  HTTPStatuses:map[string]int{},Protocols:map[string]int{},ALPN:map[string]int{},Samples:[]BackendSample{},
 }
}
func recordBackendSample(s *BackendSampleStatistics,p PinnedBackendProbe){
 s.Completed++
 entry:=BackendSample{Index:s.Completed,Status:p.Status,DurationMS:p.DurationMS,
  HTTPStatusCode:p.HTTPStatusCode,HTTPProtocol:p.HTTPProtocol,TLSALPN:p.TLSALPN,ErrorCode:p.ErrorCode}
 s.Samples=append(s.Samples,entry)
 switch p.Status{
 case "ok":s.HTTP2xx++
 case "redirect":s.Redirects++
 case "restricted":s.Restricted++
 default:s.Errors++
 }
 if p.HTTPStatusCode!=0{s.HTTPStatuses[httpStatusLabel(p.HTTPStatusCode)]++}
 if p.HTTPProtocol!=""{s.Protocols[p.HTTPProtocol]++}
 if p.TLSALPN!=""{s.ALPN[p.TLSALPN]++}
}
func httpStatusLabel(code int)string{
 if code<100||code>599{return "other"}
 return string(rune('0'+code/100))+string(rune('0'+code/10%10))+string(rune('0'+code%10))
}
func finalizeSampleStats(s *BackendSampleStatistics){
 // Latency percentiles include only attempts with an HTTP response;
 // errors/timeouts are counted independently and never treated as 0 ms.
 durations:=[]int64{}
 for _,p:=range s.Samples{
  if p.HTTPStatusCode>0{durations=append(durations,p.DurationMS)}
 }
 s.MinMS,s.MedianMS,s.P95MS,s.MaxMS=sampleDurationPercentiles(durations)
}
func repeatPinnedBackendSamples(ctx context.Context,plan DiagnosticPlan,first PinnedBackendReport,repeats int,timeout time.Duration,probe PinnedSampleFn)BackendSampling{
 result:=BackendSampling{Requested:repeats,Nodes:[]BackendSampleStatistics{}}
 if repeats<1||repeats>maxPinnedRepeat{return result}
 result.TotalPlanned=len(first.Results)*repeats
 for _,initial:=range first.Results{
  st:=buildSampleStats(initial,repeats)
  recordBackendSample(&st,initial)
  result.Nodes=append(result.Nodes,st)
 }
 // Round-robin additional observations avoid always sampling the first IP
 // more times before reaching the last. Each request has a bounded timeout.
 for attempt:=1;attempt<repeats;attempt++{
  for i:=range result.Nodes{
   if ctx.Err()!=nil{break}
   localCtx,cancel:=context.WithTimeout(ctx,timeout)
   p:=probe(localCtx,plan,result.Nodes[i].IP)
   cancel()
   recordBackendSample(&result.Nodes[i],p)
  }
  if ctx.Err()!=nil{break}
 }
 for i:=range result.Nodes{
  finalizeSampleStats(&result.Nodes[i])
  result.TotalCompleted+=result.Nodes[i].Completed
 }
 result.Incomplete=result.TotalCompleted<result.TotalPlanned
 return result
}
