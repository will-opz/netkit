package main

import (
 "encoding/json"
 "strings"
 "testing"
)

func TestAIDiagnosticEvidenceCorpus(t *testing.T){
 // These are synthetic, deterministic regressions: no model or public
 // network is contacted. They pin factual fields and citation boundaries.
 cases:=[]struct{
  name string
  layer string
  status string
  code string
  tStatus string
  hStatus string
  httpCodes []int
  skipped bool
 }{
  {"dns_resolver_failure","dns","failed","dns_error","","",nil,false},
  {"dns_timeout","dns","failed","timeout","","",nil,false},
  {"dns_no_usable_address","dns","failed","dns_error","","",nil,false},
  {"dns_ipv4_only","dns","ok","","","",nil,false},
  {"dns_dual_stack","dns","ok","","","",nil,false},
  {"tcp_refused","tcp","failed","connect_error","connect_error","",nil,false},
  {"tcp_timeout","tcp","failed","timeout","timeout","",nil,false},
  {"tcp_connected","tcp","ok","","connected","",nil,false},
  {"tls_hostname_mismatch","tls","failed","hostname_mismatch","","",nil,false},
  {"tls_untrusted_authority","tls","failed","untrusted_authority","","",nil,false},
  {"tls_expired","tls","failed","cert_expired","","",nil,false},
  {"tls_handshake_error","tls","failed","tls_handshake_failed","","",nil,false},
  {"tls_verified","tls","ok","","","",nil,false},
  {"http_403","http","restricted","","","restricted",[]int{403},false},
  {"http_429","http","restricted","","","restricted",[]int{429},false},
  {"http_503","http","failed","http_error","","http_error",[]int{503},false},
  {"http_timeout","http","failed","timeout","","timeout",nil,false},
  {"http_301_then_200","http","ok","","","ok",[]int{301,200},false},
  {"http_redirect_loop","http","failed","redirect_loop","","redirect_loop",[]int{301},false},
  {"http_not_run_after_tls_error","http","skipped","","","",nil,true},
 }
 for _,tc:=range cases{
  t.Run(tc.name,func(t *testing.T){
   s:=DiagnosticStage{ID:tc.layer+".1",Layer:tc.layer,Status:tc.status,Error:tc.code,DurationMS:11}
   switch tc.layer{
   case "dns":
    s.DNS=&DiagnosticDNS{Host:"example.com",IPs:[]string{"93.184.215.14"}}
   case "tcp":
    s.TCP=&TCPReport{Status:tc.tStatus}
   case "tls":
    s.TLS=&TLSReport{Connected:true,Verified:tc.status=="ok",VerificationCode:tc.code}
   case "http":
    if !tc.skipped{
     s.HTTP=&HTTPReport{Status:tc.hStatus}
     for _,code:=range tc.httpCodes{s.HTTP.Hops=append(s.HTTP.Hops,HTTPHop{StatusCode:code})}
     s.HTTP.Redirects=0
     if len(tc.httpCodes)>1{s.HTTP.Redirects=len(tc.httpCodes)-1}
    }
   }
   bundle:=EvidenceBundle{Observer:"local_machine",Plan:DiagnosticPlan{Host:"example.com"},Stages:[]DiagnosticStage{s}}
   projected:=evidenceForAI(bundle)
   if len(projected.Stages)!=1||projected.Stages[0].ID!=s.ID||projected.Stages[0].Status!=tc.status{
    t.Fatalf("projection stage mismatch: %+v",projected)
   }
   b,err:=json.Marshal(projected)
   if err!=nil{t.Fatal(err)}
   if strings.Contains(string(b),"93.184.215.14"){t.Fatal("resolved IP leaked")}
   if tc.layer=="http"&&!tc.skipped{
    if len(projected.Stages[0].HTTPStatusCodes)!=len(tc.httpCodes){t.Fatalf("lost HTTP codes: %+v",projected)}
   }
   if tc.skipped{
    a:=AIAnalysis{Summary:"Unmeasured",EvidenceIDs:[]string{s.ID}}
    if err:=validateAIAnalysis(a,bundle);err==nil{t.Fatal("skipped-only summary accepted")}
   }else{
    a:=AIAnalysis{Summary:"Observed",EvidenceIDs:[]string{s.ID},Hypotheses:[]AIHypothesis{{Cause:"Possible cause",Confidence:"low",EvidenceIDs:[]string{s.ID}}}}
    if err:=validateAIAnalysis(a,bundle);err!=nil{t.Fatal(err)}
   }
  })
 }
}
func TestAIHypothesesCannotCiteSkippedStage(t *testing.T){
 b:=aiFixtureBundle()
 hypothesis:=AIAnalysis{Summary:"TLS mismatch",EvidenceIDs:[]string{"tls.1"},
  Hypotheses:[]AIHypothesis{{Cause:"HTTP was blocked by a CDN",Confidence:"high",EvidenceIDs:[]string{"http.1"}}}}
 if err:=validateAIAnalysis(hypothesis,b);err==nil{t.Fatal("skipped HTTP cannot establish CDN cause")}
 hypothesis.Hypotheses[0].EvidenceIDs=[]string{"tls.1"}
 if err:=validateAIAnalysis(hypothesis,b);err!=nil{t.Fatalf("observed evidence should remain valid: %v",err)}
}
func TestAIStageProjectionRedirectAndTiming(t *testing.T){
 b:=aiFixtureBundle()
 b.Stages[3]=DiagnosticStage{ID:"http.1",Layer:"http",Status:"ok",DurationMS:432,HTTP:&HTTPReport{
  Status:"ok",Redirects:1,HTTPSDowngrade:true,
  Hops:[]HTTPHop{{StatusCode:301,URL:"https://example.com/?token=secret"},{StatusCode:200,URL:"http://example.com/"}},
 }}
 data:=evidenceForAI(b)
 h:=data.Stages[3]
 if h.DurationMS!=432||h.RedirectCount!=1||!h.HTTPSDowngrade||len(h.HTTPStatusCodes)!=2{
  t.Fatalf("missing redirect context: %+v",h)
 }
 blob,_:=json.Marshal(data)
 if strings.Contains(string(blob),"token=secret"){t.Fatal("URL query leaked into AI payload")}
}
func TestAITextFormatShowsEvidenceAndHypotheses(t *testing.T){
 a:=AIAnalysis{Model:"test-model",Summary:"TLS validation failed",EvidenceIDs:[]string{"dns.1","tls.1"},
  Hypotheses:[]AIHypothesis{{Cause:"wrong certificate on listener",Confidence:"medium",EvidenceIDs:[]string{"tls.1"}}},
  NextChecks:[]string{"Check SAN and SNI"},
 }
 out:=formatAIAnalysis(a,"zh")
 for _,token:=range []string{"test-model","TLS validation failed","证据","tls.1","置信度","medium","Check SAN and SNI"}{
  if !strings.Contains(out,token){t.Fatalf("missing %q in %q",token,out)}
 }
 en:=formatAIAnalysis(a,"en")
 if !strings.Contains(en,"Possible causes")||!strings.Contains(en,"Suggested next checks"){t.Fatalf("English labels absent: %s",en)}
}
