package main

import (
 "context"
 "encoding/json"
 "net"
 "net/http"
 "reflect"
 "strings"
 "testing"
 "time"
)

func syntheticTemporalEvidence(target string,ips []string,status string)EvidenceBundle{
 plan,_:=parseDiagnosticTarget(target)
 stages:=[]DiagnosticStage{
  {ID:"dns.1",Layer:"dns",Status:"ok",DNS:&DiagnosticDNS{Host:plan.Host,IPs:ips}},
  {ID:"tcp.1",Layer:"tcp",Status:"ok",TCP:&TCPReport{Status:"connected"}},
  {ID:"tls.1",Layer:"tls",Status:"ok",TLS:&TLSReport{Verified:true,Connected:true}},
  {ID:"http.1",Layer:"http",Status:"ok",HTTP:&HTTPReport{Status:"ok",Hops:[]HTTPHop{{StatusCode:200}}}},
 }
 if status!="ok"{
  stages[1].Status="failed"
  stages[1].Error="connect_error"
  stages[2].Status="skipped"
  stages[3].Status="skipped"
 }
 e:=EvidenceBundle{SchemaVersion:"1",Plan:plan,Observer:"local_machine",
  Status:status,Stages:stages,DurationMS:123,
  ObservedAt:time.Now().UTC().Format(time.RFC3339)}
 if status!="ok"{e.FirstFailure="tcp.1"}
 return e
}
func TestTemporalSamplingFreshProbeAndDNSRotation(t *testing.T){
 first:=syntheticTemporalEvidence("example.com",[]string{"1.1.1.1","2.2.2.2"},"ok")
 next:=[][]string{
  {"2.2.2.2","1.1.1.1"}, // reordering alone does not count
  {"2.2.2.2","3.3.3.3"},
 }
 calls:=0
 result:=sampleDomainOverTime(context.Background(),first,3,time.Millisecond,time.Second,
  func(ctx context.Context,plan DiagnosticPlan,d time.Duration)EvidenceBundle{
   if d!=time.Second||plan.Host!="example.com"{t.Fatal("wrong diagnostic plan")}
   ips:=next[calls]
   calls++
   return syntheticTemporalEvidence("example.com",ips,"ok")
  })
 if calls!=2||result.Completed!=3||result.DNSChanges!=1||
  result.FailedRounds!=0||result.Status!="dns_addresses_changed"{
  t.Fatalf("bad temporal evidence: %+v",result)
 }
 if !reflect.DeepEqual(result.Rounds[0].ResolvedIPs,[]string{"1.1.1.1","2.2.2.2"}){
  t.Fatalf("first round modified: %+v",result.Rounds[0])
 }
 for i,round:=range result.Rounds{
  if round.ID!="round."+string(rune('1'+i))||round.HTTPStatus!="ok"||round.FinalHTTPCode!=200{
   t.Fatalf("bad round: %+v",round)
  }
 }
}
func TestTemporalSamplingFailureAndRecovery(t *testing.T){
 first:=syntheticTemporalEvidence("example.com",[]string{"1.1.1.1"},"ok")
 round:=0
 result:=sampleDomainOverTime(context.Background(),first,3,time.Millisecond,time.Second,
  func(context.Context,DiagnosticPlan,time.Duration)EvidenceBundle{
   round++
   if round==1{return syntheticTemporalEvidence("example.com",[]string{"1.1.1.1"},"failed")}
   return syntheticTemporalEvidence("example.com",[]string{"1.1.1.1"},"ok")
  })
 if result.Status!="intermittent_or_failed"||result.FailedRounds!=1||
  result.HealthyRounds!=2||result.DNSChanges!=0||result.Rounds[1].FirstFailure!="tcp.1"{
  t.Fatalf("failure/recovery lost: %+v",result)
 }
}
func TestTemporalSamplingCancelledPreservesPartial(t *testing.T){
 first:=syntheticTemporalEvidence("example.com",[]string{"1.1.1.1"},"ok")
 ctx,cancel:=context.WithCancel(context.Background())
 cancel()
 result:=sampleDomainOverTime(ctx,first,10,time.Second,time.Second,
  func(context.Context,DiagnosticPlan,time.Duration)EvidenceBundle{
   t.Fatal("cancelled probe must not run")
   return EvidenceBundle{}
  })
 if !result.Incomplete||result.Completed!=1||result.Status!="incomplete"{t.Fatalf("partial result lost: %+v",result)}
}
func TestTemporalAIProjectionRedactsRotatingPrivateIPs(t *testing.T){
 b:=syntheticTemporalEvidence("example.com",[]string{"1.1.1.1"},"ok")
 t1:=temporalRoundFromEvidence(b,1)
 t2:=temporalRoundFromEvidence(syntheticTemporalEvidence("example.com",[]string{"10.1.2.3"},"ok"),2)
 b.Temporal=&TemporalSampling{Requested:2,Completed:2,Status:"dns_addresses_changed",
  HealthyRounds:2,DNSChanges:1,Rounds:[]TemporalRound{t1,t2}}
 if !privateAITarget(b){t.Fatal("later private resolution must gate remote AI")}
 projection:=evidenceForAI(b)
 data,err:=json.Marshal(projection)
 if err!=nil{t.Fatal(err)}
 if strings.Contains(string(data),"10.1.2.3")||strings.Contains(string(data),"1.1.1.1"){
  t.Fatalf("IP leak in AI temporal summary: %s",data)
 }
 if projection.Temporal==nil||projection.Temporal.DNSChanges!=1{
  t.Fatalf("temporal summary missing: %+v",projection)
 }
 a:=AIAnalysis{Summary:"round two recovered",EvidenceIDs:[]string{"round.2"}}
 if err:=validateAIAnalysis(a,b);err!=nil{t.Fatalf("round citation invalid: %v",err)}
 a.EvidenceIDs=[]string{"round.3"}
 if err:=validateAIAnalysis(a,b);err==nil{t.Fatal("invented round accepted")}
}
func TestTemporalSnapshotFromActualDeterministicDiagnose(t *testing.T){
 plan,_:=parseDiagnosticTarget("http://example.com")
 p:=mockDiagnosticProbes()
 p.Resolve=func(context.Context,string)([]net.IPAddr,error){
  return []net.IPAddr{{IP:net.ParseIP("192.0.2.1")}},nil
 }
 p.HTTP=func(context.Context,*http.Client,string,int)HTTPReport{
  return HTTPReport{Status:"ok",Hops:[]HTTPHop{{StatusCode:301},{StatusCode:200}},Redirects:1}
 }
 b:=diagnose(context.Background(),plan,time.Second,p)
 r:=temporalRoundFromEvidence(b,1)
 if r.FinalHTTPCode!=200||r.TLSStatus!=""||r.DNSStatus!="ok"||len(r.ResolvedIPs)!=1{
  t.Fatalf("missing real diagnostic provenance: %+v",r)
 }
}
