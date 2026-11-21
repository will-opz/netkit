package main

import (
 "context"
 "crypto/tls"
 "crypto/x509"
 "errors"
 "fmt"
 "net"
 "net/http"
 "net/http/httptrace"
 "net/url"
 "strconv"
 "strings"
 "time"
)

const maxPinnedIPChecks = 8

// PinnedBackendProbe is a single GET of the origin root over a new TCP
// connection to a *specific DNS result*. The URL hostname (and therefore
// HTTP Host, TLS SNI and certificate hostname verification) remains unchanged.
// Redirects are recorded but never followed: they can change host/IP/scheme.
type PinnedBackendProbe struct {
 ID string `json:"id"`
 IP string `json:"ip"`
 ConnectedIP string `json:"connected_ip,omitempty"`
 ConnectionMode string `json:"connection_mode"`
 HTTPProtocol string `json:"http_protocol,omitempty"`
 TLSALPN string `json:"tls_alpn,omitempty"`
 TLSVersion string `json:"tls_version,omitempty"`
 Status string `json:"status"`
 DurationMS int64 `json:"duration_ms"`
 TLSVerified *bool `json:"tls_verified,omitempty"`
 TLSCode string `json:"tls_code,omitempty"`
 HTTPStatusCode int `json:"http_status_code,omitempty"`
 RedirectHost string `json:"redirect_host,omitempty"`
 ErrorCode string `json:"error_code,omitempty"`
}
type PinnedBackendReport struct {
 Status string `json:"status"`
 Results []PinnedBackendProbe `json:"results"`
 Checked int `json:"checked"`
 TotalResolved int `json:"total_resolved"`
 Truncated bool `json:"truncated,omitempty"`
 SuccessCount int `json:"success_count"` // legacy: first-hop response, including redirect/restricted
 FailureCount int `json:"failure_count"`
 OKCount int `json:"ok_count"`
 RedirectCount int `json:"redirect_count"`
 RestrictedCount int `json:"restricted_count"`
 HTTPErrorCount int `json:"http_error_count"`
 TransportErrorCount int `json:"transport_error_count"`
 Assessment string `json:"assessment"`
}

// pinnedBackendProbe does not use the system proxy. The only remote TCP
// destination it can dial is the selected resolved IP and target port.
// A root-only GET avoids retrieving arbitrary large response bodies.
func pinnedBackendProbe(ctx context.Context,plan DiagnosticPlan,ip string)(out PinnedBackendProbe){
 return pinnedBackendProbeWithRoots(ctx,plan,ip,nil)
}
func pinnedBackendProbeWithRoots(ctx context.Context,plan DiagnosticPlan,ip string,roots *x509.CertPool)(out PinnedBackendProbe){
 start:=time.Now()
 out= PinnedBackendProbe{IP:ip,Status:"unknown",ConnectionMode:"direct_pinned_no_proxy"}
 defer func(){out.DurationMS=time.Since(start).Milliseconds()}()
 parsed:=net.ParseIP(ip)
 if parsed==nil{out.Status="invalid_ip";out.ErrorCode="invalid_ip";return out}
 addr:=net.JoinHostPort(ip,strconv.Itoa(plan.Port))
 destHostPort:=net.JoinHostPort(plan.Host,strconv.Itoa(plan.Port))
 var connected bool
 var tlsStarted bool
 var tlsSucceeded bool
 trace:=&httptrace.ClientTrace{
  GotConn:func(info httptrace.GotConnInfo){
   connected=true
   if info.Conn!=nil{
    if remote,ok:=info.Conn.RemoteAddr().(*net.TCPAddr);ok{out.ConnectedIP=remote.IP.String()}
   }
  },
  TLSHandshakeStart:func(){tlsStarted=true},
  TLSHandshakeDone:func(state tls.ConnectionState,err error){
   if err==nil{
    tlsSucceeded=true
    out.TLSVersion=tlsVersionName(state.Version)
    out.TLSALPN=state.NegotiatedProtocol
   }
  },
 }
 transport:=&http.Transport{
  Proxy:nil,
  DisableKeepAlives:true,
  // HTTP/2 must be negotiated explicitly; forcing HTTP/1.1 would
  // make real CDN ALPN comparisons misleading.
  ForceAttemptHTTP2:true,
  TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS12,RootCAs:roots},
  DialContext:func(ctx context.Context,network,requested string)(net.Conn,error){
   if !strings.EqualFold(requested,destHostPort){
    return nil,errors.New("unexpected dial target")
   }
   return (&net.Dialer{}).DialContext(ctx,"tcp",addr)
  },
 }
 defer transport.CloseIdleConnections()
 client:=&http.Client{
  Transport:transport,
  CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse},
 }
 target:=&url.URL{Scheme:plan.Scheme,Host:destHostPort,Path:"/"}
 req,err:=http.NewRequestWithContext(httptrace.WithClientTrace(ctx,trace),http.MethodGet,target.String(),nil)
 if err!=nil{out.Status="request_error";out.ErrorCode="request_error";return out}
 req.Header.Set("User-Agent",agent)
 response,err:=client.Do(req)
 if err!=nil{
  if errors.Is(err,context.DeadlineExceeded)||errors.Is(ctx.Err(),context.DeadlineExceeded){
   out.Status="timeout";out.ErrorCode="timeout";return out
  }
  var ne net.Error
  if errors.As(err,&ne)&&ne.Timeout(){out.Status="timeout";out.ErrorCode="timeout";return out}
  if tlsStarted||tlsSucceeded{
   out.Status="tls_error"
   out.ErrorCode=classifyTLSVerification(err,nil,time.Now())
   if out.ErrorCode=="certificate_verification_failed"{
    out.ErrorCode="tls_verification_failed"
   }
  }else if !connected{
   out.Status="tcp_error";out.ErrorCode="tcp_connect_failed"
  }else{
   out.Status="network_error";out.ErrorCode="network_error"
  }
  if plan.Scheme=="https"&&(tlsStarted||tlsSucceeded){
   verified:=false
   out.TLSVerified=&verified
  }
  return out
 }
 defer response.Body.Close()
 out.HTTPProtocol=response.Proto
 if plan.Scheme=="https"{
  verified:=response.TLS!=nil&&len(response.TLS.VerifiedChains)>0
  out.TLSVerified=&verified
  if !verified{out.Status="tls_error";out.ErrorCode="tls_verification_failed";return out}
  out.TLSVersion=tlsVersionName(response.TLS.Version)
  out.TLSALPN=response.TLS.NegotiatedProtocol
 }
 out.HTTPStatusCode=response.StatusCode
 out.Status=httpState(response.StatusCode)
 if out.Status=="redirect_incomplete"{
  out.Status="redirect"
  if location:=response.Header.Get("Location");location!=""{
   if redirected,err:=url.Parse(location);err==nil{
    out.RedirectHost=req.URL.ResolveReference(redirected).Hostname()
   }
  }
 }
 if out.Status=="ok"||out.Status=="redirect"||out.Status=="restricted"{return out}
 if out.Status=="http_error"{out.ErrorCode="http_error"}else{out.ErrorCode="http_unexpected_status"}
 return out
}

// probePinnedBackends checks at most eight unique IPs sequentially, under
// both a per-IP timeout and one overall bound. Results always describe local
// observations only. DNS is never re-resolved inside the pinned checks.
func probePinnedBackends(ctx context.Context,plan DiagnosticPlan,ips []string,timeout time.Duration)PinnedBackendReport{
 out:=PinnedBackendReport{Status:"unknown",Results:[]PinnedBackendProbe{}}
 unique:=[]string{}
 seen:=map[string]bool{}
 for _,ip:=range ips{
  if seen[ip]{continue}
  if net.ParseIP(ip)==nil{continue}
  seen[ip]=true
  unique=append(unique,ip)
 }
 out.TotalResolved=len(unique)
 if len(unique)>maxPinnedIPChecks{unique=unique[:maxPinnedIPChecks];out.Truncated=true}
 for i,ip:=range unique{
  checkCtx,cancel:=context.WithTimeout(ctx,timeout)
  probe:=pinnedBackendProbe(checkCtx,plan,ip)
  cancel()
  probe.ID=fmt.Sprintf("backend.%d",i+1)
  out.Results=append(out.Results,probe)
  if probe.Status=="ok"||probe.Status=="redirect"||probe.Status=="restricted"{
   out.SuccessCount++
  }else{
   out.FailureCount++
  }
  if ctx.Err()!=nil{break}
 }
 out.Checked=len(out.Results)
 classifyPinnedBackendReport(&out)
 return out
}


func classifyPinnedBackendReport(r *PinnedBackendReport){
 r.OKCount=0
 r.RedirectCount=0
 r.RestrictedCount=0
 r.HTTPErrorCount=0
 r.TransportErrorCount=0
 for _,p:=range r.Results{
  switch p.Status{
  case "ok":r.OKCount++
  case "redirect":r.RedirectCount++
  case "restricted":r.RestrictedCount++
  case "http_error":r.HTTPErrorCount++
  default:r.TransportErrorCount++
  }
 }
 // Assessment describes exactly what was observed, not full-site health.
 switch{
 case r.Checked==0:r.Status="not_checked";r.Assessment="no_backend_checked"
 case r.FailureCount>0&&r.SuccessCount>0:
  r.Status="partial_failure";r.Assessment="mixed_first_hop_success_and_failure"
 case r.FailureCount>0:
  r.Status="failed";r.Assessment="all_checked_first_hops_failed"
 case r.Truncated||r.Checked<r.TotalResolved:
  r.Status="incomplete";r.Assessment="incomplete_backend_coverage"
 case r.OKCount==r.Checked:
  r.Status="reachable";r.Assessment="all_checked_first_hops_http_2xx"
 case r.RedirectCount==r.Checked:
  r.Status="redirect_only";r.Assessment="all_checked_first_hops_redirect_unfollowed"
 case r.RestrictedCount==r.Checked:
  r.Status="restricted_only";r.Assessment="all_checked_first_hops_access_restricted"
 default:
  r.Status="mixed_responses";r.Assessment="mixed_first_hop_http_responses"
 }
}
