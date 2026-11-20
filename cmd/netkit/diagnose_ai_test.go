package main

import (
 "context"
 "encoding/json"
 "io"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)

func aiFixtureBundle()EvidenceBundle{
 return EvidenceBundle{
  SchemaVersion:"1",Observer:"local_machine",
  Plan:DiagnosticPlan{Host:"example.com",Scheme:"https",Port:443},
  Status:"failed",FirstFailure:"tls.1",
  Stages:[]DiagnosticStage{
   {ID:"dns.1",Layer:"dns",Status:"ok",DNS:&DiagnosticDNS{Host:"example.com",IPs:[]string{"93.184.215.14"}}},
   {ID:"tcp.1",Layer:"tcp",Status:"ok",TCP:&TCPReport{Status:"connected"}},
   {ID:"tls.1",Layer:"tls",Status:"failed",Error:"hostname_mismatch",TLS:&TLSReport{Connected:true,Verified:false,VerificationCode:"hostname_mismatch",Subject:"sensitive.internal",ConnectionError:"SECRET-TOKEN"}},
   {ID:"http.1",Layer:"http",Status:"skipped",Error:"do not send secret"},
  },
 }
}
func TestAIEvidenceProjectionAndSecrets(t *testing.T){
 b:=aiFixtureBundle()
 data,err:=json.Marshal(evidenceForAI(b))
 if err!=nil{t.Fatal(err)}
 s:=string(data)
 for _,secret:=range []string{"SECRET-TOKEN","sensitive.internal","93.184.215.14","do not send secret"}{
  if strings.Contains(s,secret){t.Fatalf("raw sensitive field leaked: %s",secret)}
 }
 for _,key:=range []string{"tls.1","hostname_mismatch","example.com"}{
  if !strings.Contains(s,key){t.Fatalf("missing relevant evidence: %s",key)}
 }
}
func TestAIPrivateScope(t *testing.T){
 b:=aiFixtureBundle()
 for _,host:=range []string{"localhost","192.168.1.1","127.0.0.1","db.internal","app.local","node.test"}{
  b.Plan.Host=host
  if !privateAITarget(b){t.Errorf("private target passed: %s",host)}
 }
 b.Plan.Host="example.com"
 if privateAITarget(b){t.Fatal("public target mistakenly private")}
 b.Stages[0].DNS.IPs=[]string{"10.2.3.4"}
 if !privateAITarget(b){t.Fatal("internal resolution must trigger privacy gate")}
}
func TestAIEndpointPolicy(t *testing.T){
 for _,raw:=range []string{"http://example.com/v1","ftp://example.com/v1","http://user:key@example.com/v1","https://example.com/v1?token=secret"}{
  if _,_,err:=aiEndpoint(raw);err==nil{t.Errorf("accepted insecure/invalid AI endpoint %s",raw)}
 }
 endpoint,local,err:=aiEndpoint("http://127.0.0.1:11434/v1")
 if err!=nil||!local||endpoint!="http://127.0.0.1:11434/v1/chat/completions"{t.Fatalf("local endpoint: %s %t %v",endpoint,local,err)}
 endpoint,local,err=aiEndpoint("https://api.openai.com/v1")
 if err!=nil||local||endpoint!="https://api.openai.com/v1/chat/completions"{t.Fatalf("remote endpoint: %s %t %v",endpoint,local,err)}
}
func TestAIAnalysisEvidenceValidation(t *testing.T){
 b:=aiFixtureBundle()
 good:=AIAnalysis{
  Summary:"TLS certificate does not match target",EvidenceIDs:[]string{"tls.1"},
  Hypotheses:[]AIHypothesis{{Cause:"wrong certificate",Confidence:"medium",EvidenceIDs:[]string{"tls.1"}}},
  NextChecks:[]string{"Inspect SAN"},
 }
 if err:=validateAIAnalysis(good,b);err!=nil{t.Fatal(err)}
 good.EvidenceIDs=[]string{"tls.999"}
 if err:=validateAIAnalysis(good,b);err==nil{t.Fatal("unknown evidence accepted")}
 good.EvidenceIDs=[]string{"tls.1"}
 good.Hypotheses[0].Confidence="certain"
 if err:=validateAIAnalysis(good,b);err==nil{t.Fatal("invalid confidence accepted")}
}
func TestOpenAICompatibleAnalysis(t *testing.T){
 b:=aiFixtureBundle()
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.URL.Path!="/v1/chat/completions"{t.Errorf("wrong endpoint: %s",r.URL.Path)}
  if r.Header.Get("Authorization")!=""{t.Error("unexpected auth header")}
  body,err:=io.ReadAll(r.Body)
  if err!=nil{t.Fatal(err)}
  if !strings.Contains(string(body),"\"model\":\"qwen3:8b\""){t.Errorf("model omitted")}
  if strings.Contains(string(body),"SECRET-TOKEN"){t.Error("secret leaked")}
  w.Header().Set("Content-Type","application/json")
  w.Write([]byte(`{"choices":[{"message":{"content":"{\"summary\":\"TLS issue\",\"evidence_ids\":[\"tls.1\"],\"hypotheses\":[{\"cause\":\"Certificate mismatch\",\"confidence\":\"high\",\"evidence_ids\":[\"tls.1\"]}],\"next_checks\":[\"Check SAN\"]}"}}]}`))
 }))
 defer server.Close()
 settings:=AISettings{BaseURL:server.URL+"/v1",Model:"qwen3:8b",Timeout:time.Second}
 got,err:=analyzeWithAI(context.Background(),b,settings,server.Client())
 if err!=nil||got==nil||got.Summary!="TLS issue"||got.Model!="qwen3:8b"{t.Fatalf("analysis %+v: %v",got,err)}
}
func TestLocalAIAllowedForPrivateEvidence(t *testing.T){
 b:=aiFixtureBundle()
 b.Plan.Host="localhost"
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Content-Type","application/json")
  w.Write([]byte(`{"choices":[{"message":{"content":"{\"summary\":\"Local test\",\"evidence_ids\":[\"tls.1\"],\"hypotheses\":[],\"next_checks\":[]}"}}]}`))
 }))
 defer server.Close()
 got,err:=analyzeWithAI(context.Background(),b,AISettings{BaseURL:server.URL+"/v1",Model:"qwen3:8b",Timeout:time.Second},server.Client())
 if err!=nil||got==nil{t.Fatalf("local model should allow private diagnosis: %v",err)}
}
func TestAIFailureIsolation(t *testing.T){
 b:=aiFixtureBundle()
 cases:=[]string{
  `{"choices":[{"message":{"content":"not-json"}}]}`,
  `{"choices":[{"message":{"content":"{\"summary\":\"no evidence\",\"evidence_ids\":[\"fake.1\"]}"}}]}`,
  `{"choices":[]}`,
 }
 for _,body:=range cases{
  server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.Write([]byte(body))}))
  settings:=AISettings{BaseURL:server.URL+"/v1",Model:"test",Timeout:time.Second}
  _,err:=analyzeWithAI(context.Background(),b,settings,server.Client())
  server.Close()
  if err==nil{t.Fatalf("invalid model response accepted: %s",body)}
 }
 settings:=AISettings{Model:"test",Timeout:time.Second}
 _,err:=analyzeWithAI(context.Background(),b,settings,nil)
 if err==nil||!strings.Contains(err.Error(),"API_KEY"){t.Fatalf("remote key not enforced: %v",err)}
 b.Plan.Host="localhost"
 _,err=analyzeWithAI(context.Background(),b,settings,nil)
 if err==nil||!strings.Contains(err.Error(),"private"){t.Fatalf("private target not protected: %v",err)}
}
