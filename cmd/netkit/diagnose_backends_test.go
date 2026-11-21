package main

import (
 "context"
 "encoding/json"
 "crypto/x509"
 "net"
 "net/http"
 "net/http/httptest"
 "strconv"
 "strings"
 "sync/atomic"
 "testing"
 "time"
)

func TestPinnedHTTPUsesSelectedIPButOriginalHost(t *testing.T){
 var hostSeen string
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  hostSeen=r.Host
  w.Header().Set("Location","https://external.example.org/login?access_token=SECRET")
  w.WriteHeader(http.StatusMovedPermanently)
 }))
 defer server.Close()
 port,_:=strconv.Atoi(strings.TrimPrefix(server.URL,"http://127.0.0.1:"))
 plan:=DiagnosticPlan{Host:"example.com",Port:port,Scheme:"http"}
 got:=pinnedBackendProbe(context.Background(),plan,"127.0.0.1")
 if got.Status!="redirect"||got.HTTPStatusCode!=301||got.RedirectHost!="external.example.org"{
  t.Fatalf("wrong redirect outcome: %+v",got)
 }
 if got.ConnectedIP!="127.0.0.1"{t.Fatalf("not pinned: %+v",got)}
 if hostSeen!=net.JoinHostPort("example.com",strconv.Itoa(port)){t.Fatalf("Host changed to IP: %q",hostSeen)}
}
func TestPinnedTLSDefaultVerifiesAndTestRootsCanTrust(t *testing.T){
 server:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.WriteHeader(http.StatusOK)
 }))
 defer server.Close()
 port,_:=strconv.Atoi(strings.TrimPrefix(server.URL,"https://127.0.0.1:"))
 plan:=DiagnosticPlan{Host:"127.0.0.1",Port:port,Scheme:"https"}
 rejected:=pinnedBackendProbe(context.Background(),plan,"127.0.0.1")
 if rejected.Status!="tls_error"{t.Fatalf("untrusted TLS must fail: %+v",rejected)}
 if rejected.TLSVerified==nil||*rejected.TLSVerified{t.Fatalf("TLS not verified: %+v",rejected)}
 roots:=x509.NewCertPool()
 roots.AddCert(server.Certificate())
 accepted:=pinnedBackendProbeWithRoots(context.Background(),plan,"127.0.0.1",roots)
 if accepted.Status!="ok"||accepted.HTTPStatusCode!=200||accepted.ConnectedIP!="127.0.0.1"{
  t.Fatalf("pinned HTTPS failed with trusted fixture: %+v",accepted)
 }
 if accepted.TLSVerified==nil||!*accepted.TLSVerified{t.Fatalf("valid TLS not confirmed: %+v",accepted)}
}
func TestPinnedHTTPSRejectsHostnameMismatchEvenTrustedCA(t *testing.T){
 server:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.WriteHeader(200)
 }))
 defer server.Close()
 port,_:=strconv.Atoi(strings.TrimPrefix(server.URL,"https://127.0.0.1:"))
 plan:=DiagnosticPlan{Host:"definitely-not-a-certificate-name.invalid",Port:port,Scheme:"https"}
 roots:=x509.NewCertPool()
 roots.AddCert(server.Certificate())
 got:=pinnedBackendProbeWithRoots(context.Background(),plan,"127.0.0.1",roots)
 if got.Status!="tls_error"||got.HTTPStatusCode!=0{
  t.Fatalf("hostname verification was bypassed: %+v",got)
 }
}
func TestPinnedBackendsPartialFailureAndTimeout(t *testing.T){
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.WriteHeader(200)
 }))
 defer server.Close()
 port,_:=strconv.Atoi(strings.TrimPrefix(server.URL,"http://127.0.0.1:"))
 plan:=DiagnosticPlan{Host:"example.com",Port:port,Scheme:"http"}
 report:=probePinnedBackends(context.Background(),plan,[]string{"127.0.0.1","127.0.0.1","127.0.0.2"},500*time.Millisecond)
 if report.TotalResolved!=2||report.Checked!=2||report.SuccessCount!=1||report.FailureCount!=1||report.Status!="partial_failure"{
  t.Fatalf("partial results not isolated: %+v",report)
 }
}
func TestPinnedBackendsBoundedAndNoRedirectFollowing(t *testing.T){
 var calls atomic.Int32
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  calls.Add(1)
  w.Header().Set("Location","http://127.0.0.1:1/not-followed")
  w.WriteHeader(http.StatusFound)
 }))
 defer server.Close()
 port,_:=strconv.Atoi(strings.TrimPrefix(server.URL,"http://127.0.0.1:"))
 plan:=DiagnosticPlan{Host:"example.com",Port:port,Scheme:"http"}
 addresses:=[]string{"127.0.0.1"}
 for i:=2;i<14;i++{addresses=append(addresses,"127.0.0."+strconv.Itoa(i))}
 report:=probePinnedBackends(context.Background(),plan,addresses,50*time.Millisecond)
 if !report.Truncated||report.Checked!=maxPinnedIPChecks||report.TotalResolved!=13{
  t.Fatalf("missing probe bound: %+v",report)
 }
 if calls.Load()!=1{t.Fatalf("redirect or unexpected IP was contacted: %d",calls.Load())}
}

func TestAIBackendSummaryRedactsIPAndSupportsCitations(t *testing.T){
 bundle:=aiFixtureBundle()
 bundle.Backends=&PinnedBackendReport{
  Status:"partial_failure",TotalResolved:2,Checked:2,SuccessCount:1,FailureCount:1,
  Results:[]PinnedBackendProbe{
   {ID:"backend.1",IP:"192.0.2.1",ConnectedIP:"192.0.2.1",Status:"redirect",HTTPStatusCode:301,RedirectHost:"internal.secrets.example"},
   {ID:"backend.2",IP:"192.0.2.2",ConnectedIP:"192.0.2.2",Status:"tcp_error",ErrorCode:"tcp_connect_failed"},
  },
 }
 projection:=evidenceForAI(bundle)
 raw,err:=json.Marshal(projection)
 if err!=nil{t.Fatal(err)}
 for _,forbidden:=range []string{"192.0.2.1","192.0.2.2","internal.secrets.example"}{
  if strings.Contains(string(raw),forbidden){t.Fatalf("sensitive backend detail leaked: %s",forbidden)}
 }
 if projection.Backends==nil||projection.Backends.Status!="partial_failure"||len(projection.Backends.Results)!=2{
  t.Fatalf("backend evidence missing: %+v",projection)
 }
 analysis:=AIAnalysis{Summary:"one backend failed",EvidenceIDs:[]string{"backend.1","backend.2"},
  Hypotheses:[]AIHypothesis{{Cause:"IP-specific connection failure",Confidence:"medium",EvidenceIDs:[]string{"backend.2"}}}}
 if err:=validateAIAnalysis(analysis,bundle);err!=nil{t.Fatalf("valid backend references rejected: %v",err)}
 analysis.EvidenceIDs=[]string{"backend.999"}
 if err:=validateAIAnalysis(analysis,bundle);err==nil{t.Fatal("fabricated backend ID accepted")}
}
