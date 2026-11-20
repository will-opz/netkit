package main

import (
 "context"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)

func TestHTTPTracePhasesLocalServer(t *testing.T){
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  time.Sleep(12*time.Millisecond)
  w.Header().Set("Content-Type","text/plain")
  w.WriteHeader(http.StatusOK)
 }))
 defer server.Close()
 client:=&http.Client{Timeout:2*time.Second}
 report:=traceHTTP(context.Background(),client,server.URL+"/",5)
 if report.Status!="ok"||len(report.Hops)!=1{t.Fatalf("unexpected report: %+v",report)}
 p:=report.Hops[0].Phases
 if p.ConnectMS==nil||p.TTFBMS==nil||*p.TTFBMS<5 {
  t.Fatalf("expected observed connect and TTFB: %+v",p)
 }
 if p.TLSMS!=nil {t.Fatalf("plain HTTP should not report TLS: %+v",p)}
 encoded,err:=json.Marshal(p)
 if err!=nil{t.Fatal(err)}
 if !strings.Contains(string(encoded),"ttfb_ms")||strings.Contains(string(encoded),"tls_ms"){
  t.Fatalf("unexpected phase JSON: %s",encoded)
 }
}
func TestHTTPTraceTLSLocalServer(t *testing.T){
 server:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(http.StatusNoContent)}))
 defer server.Close()
 client:=server.Client()
 report:=traceHTTP(context.Background(),client,server.URL+"/",5)
 if report.Status!="ok"||len(report.Hops)!=1{t.Fatalf("unexpected response: %+v",report)}
 p:=report.Hops[0].Phases
 if p.TLSMS==nil||p.ConnectMS==nil||p.TTFBMS==nil {
  t.Fatalf("missing TLS/TCP/TTFB stage: %+v",p)
 }
 if p.DNSMS!=nil {t.Fatalf("literal loopback address should not need DNS: %+v",p)}
}
func TestHTTPPhaseUnknownAndReusePresentation(t *testing.T){
 p:=HTTPPhases{}
 if text:=formatHTTPPhases(p,"zh");text!=""{t.Fatalf("absent stages should not show zeros: %q",text)}
 reused:=true
 p.ReusedConnection=&reused
 if !strings.Contains(formatHTTPPhases(p,"zh"),"连接复用"){t.Fatalf("missing reuse display")}
 b,err:=json.Marshal(p)
 if err!=nil{t.Fatal(err)}
 if strings.Contains(string(b),"dns_ms")||!strings.Contains(string(b),"reused_connection"){
  t.Fatalf("unexpected unknown-stage encoding: %s",b)
 }
}
func TestHTTPTracePhasePerRedirectHop(t *testing.T){
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.URL.Path=="/"{http.Redirect(w,r,"/final",http.StatusFound);return}
  w.WriteHeader(http.StatusOK)
 }))
 defer server.Close()
 report:=traceHTTP(context.Background(),&http.Client{Timeout:2*time.Second},server.URL+"/",5)
 if report.Redirects!=1||len(report.Hops)!=2{t.Fatalf("redirect not preserved: %+v",report)}
 for i,hop:=range report.Hops{
  if hop.Phases.TTFBMS==nil {t.Fatalf("missing per-hop first byte for %d: %+v",i,hop)}
 }
}
