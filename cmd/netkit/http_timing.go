package main

import (
 "context"
 "crypto/tls"
 "fmt"
 "strings"
 "net/http/httptrace"
 "sync"
 "time"
)

// HTTPPhases contains measured request-stage durations. Nil means the phase
// was not observed (e.g. connection reuse, DNS cache, mock transport or proxy).
// TCP and DNS observations may refer to a proxy, not the origin host.
type HTTPPhases struct {
 DNSMS *int64 `json:"dns_ms,omitempty"`
 ConnectMS *int64 `json:"connect_ms,omitempty"`
 TLSMS *int64 `json:"tls_ms,omitempty"`
 TTFBMS *int64 `json:"ttfb_ms,omitempty"`
 ReusedConnection *bool `json:"reused_connection,omitempty"`
}

type httpPhaseRecorder struct{
 mu sync.Mutex
 dnsStart,connStart,tlsStart,wroteRequest time.Time
 phases HTTPPhases
}
func msBetween(start time.Time) *int64 {
 if start.IsZero(){return nil}
 elapsed:=time.Since(start).Milliseconds()
 return &elapsed
}
func (r *httpPhaseRecorder)trace() *httptrace.ClientTrace {
 return &httptrace.ClientTrace{
  DNSStart:func(httptrace.DNSStartInfo){r.mu.Lock();r.dnsStart=time.Now();r.mu.Unlock()},
  DNSDone:func(httptrace.DNSDoneInfo){
   r.mu.Lock();r.phases.DNSMS=msBetween(r.dnsStart);r.mu.Unlock()
  },
  ConnectStart:func(_, _ string){r.mu.Lock();r.connStart=time.Now();r.mu.Unlock()},
  ConnectDone:func(_, _ string,_ error){
   r.mu.Lock();r.phases.ConnectMS=msBetween(r.connStart);r.mu.Unlock()
  },
  TLSHandshakeStart:func(){r.mu.Lock();r.tlsStart=time.Now();r.mu.Unlock()},
  TLSHandshakeDone:func(_ tls.ConnectionState,_ error){
   r.mu.Lock();r.phases.TLSMS=msBetween(r.tlsStart);r.mu.Unlock()
  },
  GotConn:func(info httptrace.GotConnInfo){
   r.mu.Lock();reused:=info.Reused;r.phases.ReusedConnection=&reused;r.mu.Unlock()
  },
  WroteRequest:func(_ httptrace.WroteRequestInfo){r.mu.Lock();r.wroteRequest=time.Now();r.mu.Unlock()},
  GotFirstResponseByte:func(){
   r.mu.Lock();r.phases.TTFBMS=msBetween(r.wroteRequest);r.mu.Unlock()
  },
 }
}
func (r *httpPhaseRecorder)result()HTTPPhases{
 r.mu.Lock()
 defer r.mu.Unlock()
 return r.phases
}
func withHTTPPhaseTrace(ctx context.Context,recorder *httpPhaseRecorder)context.Context{
 return httptrace.WithClientTrace(ctx,recorder.trace())
}

func formatHTTPPhases(p HTTPPhases,lang string)string {
 var items []string
 appendPhase:=func(name string,v *int64){if v!=nil{items=append(items,fmt.Sprintf("%s=%dms",name,*v))}}
 appendPhase("DNS",p.DNSMS)
 appendPhase("TCP",p.ConnectMS)
 appendPhase("TLS",p.TLSMS)
 appendPhase("TTFB",p.TTFBMS)
 if p.ReusedConnection!=nil && *p.ReusedConnection {
  if lang=="en"{items=append(items,"connection reused")
  }else{items=append(items,"连接复用")}
 }
 if len(items)==0{return ""}
 return "     "+strings.Join(items," | ")+"\n"
}
