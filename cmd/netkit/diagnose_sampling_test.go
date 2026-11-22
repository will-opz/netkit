package main

import (
 "context"
 "encoding/json"
 "strings"
 "testing"
 "time"
)

func TestPinnedRepeatStatisticsAndSampleCounts(t *testing.T){
 first:=PinnedBackendReport{Status:"reachable",Checked:2,TotalResolved:2,Results:[]PinnedBackendProbe{
  {ID:"backend.1",IP:"192.0.2.1",Status:"ok",HTTPStatusCode:200,DurationMS:10,HTTPProtocol:"HTTP/1.1",TLSALPN:"http/1.1"},
  {ID:"backend.2",IP:"192.0.2.2",Status:"ok",HTTPStatusCode:200,DurationMS:20,HTTPProtocol:"HTTP/1.1"},
 }}
 calls:=map[string]int{}
 report:=repeatPinnedBackendSamples(context.Background(),DiagnosticPlan{Host:"example.com"},
  first,3,time.Second,func(ctx context.Context,p DiagnosticPlan,ip string)PinnedBackendProbe{
   calls[ip]++
   if ip=="192.0.2.1"&&calls[ip]==2{
    return PinnedBackendProbe{IP:ip,Status:"timeout",ErrorCode:"timeout",DurationMS:40}
   }
   ms:=int64(10)
   if ip=="192.0.2.2"{ms=20}
   return PinnedBackendProbe{IP:ip,Status:"ok",HTTPStatusCode:200,DurationMS:ms,HTTPProtocol:"HTTP/1.1"}
  })
 if report.TotalCompleted!=6||report.TotalPlanned!=6||report.Incomplete||calls["192.0.2.1"]!=2||calls["192.0.2.2"]!=2{
  t.Fatalf("sample count incorrect: %+v calls=%v",report,calls)
 }
 x:=report.Nodes[0]
 if x.Completed!=3||x.HTTP2xx!=2||x.Errors!=1||x.MinMS==nil||*x.MinMS!=10||*x.MedianMS!=10||*x.P95MS!=10{
  t.Fatalf("timeout mixed with response latency: %+v",x)
 }
 if x.HTTPStatuses["200"]!=2||x.Protocols["HTTP/1.1"]!=2{t.Fatalf("status/protocol distribution lost: %+v",x)}
}
func TestPinnedRepeatCancelledDoesNotInventSamples(t *testing.T){
 first:=PinnedBackendReport{Results:[]PinnedBackendProbe{{ID:"backend.1",IP:"192.0.2.1",Status:"ok",HTTPStatusCode:200,DurationMS:5}}}
 ctx,cancel:=context.WithCancel(context.Background())
 cancel()
 r:=repeatPinnedBackendSamples(ctx,DiagnosticPlan{},first,5,time.Second,
  func(context.Context,DiagnosticPlan,string)PinnedBackendProbe{t.Fatal("probe after cancellation");return PinnedBackendProbe{}})
 if !r.Incomplete||r.TotalCompleted!=1||r.TotalPlanned!=5{t.Fatalf("partial sampling wrong: %+v",r)}
}
func TestSamplingAIProjectionDoesNotIncludeIP(t *testing.T){
 b:=aiFixtureBundle()
 st:=buildSampleStats(PinnedBackendProbe{ID:"backend.1",IP:"192.0.2.1"},3)
 recordBackendSample(&st,PinnedBackendProbe{Status:"ok",HTTPStatusCode:200,DurationMS:33})
 finalizeSampleStats(&st)
 b.Sampling=&BackendSampling{Requested:3,TotalPlanned:3,TotalCompleted:1,Incomplete:true,Nodes:[]BackendSampleStatistics{st}}
 projection:=evidenceForAI(b)
 blob,err:=json.Marshal(projection)
 if err!=nil{t.Fatal(err)}
 if strings.Contains(string(blob),"192.0.2.1"){t.Fatalf("private IP leaked: %s",blob)}
 if projection.Sampling==nil||len(projection.Sampling.Nodes)!=1||projection.Sampling.Nodes[0].MedianMS==nil{
  t.Fatalf("sampling AI stats missing: %+v",projection)
 }
}
