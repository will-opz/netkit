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
 SuccessCount int `json:"success_count"`
 FailureCount int `json:"failure_count"`
}

// pinnedBackendProbe does not use the system proxy. The only remote TCP
// destination it can dial is the selected resolved IP and target port.
// A root-only GET avoids retrieving arbitrary large response bodies.
func pinnedBackendProbe(ctx context.Context,plan DiagnosticPlan,ip string)(out PinnedBackendProbe){
 start:=time.Now()
 out= PinnedBackendProbe{IP:ip,Status:"unknown"}
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
  TLSHandshakeDone:func(_ tls.ConnectionState,err error){if err==nil{tlsSucceeded=true}},
 }
 transport:=&http.Transport{
  Proxy:nil,
  DisableKeepAlives:true,
  ForceAttemptHTTP2:false,
  TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS12},
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
  if plan.Scheme=="https"{
   verified:=false
   out.TLSVerified=&verified
  }
  return out
 }
 defer response.Body.Close()
 if plan.Scheme=="https"{
  verified:=response.TLS!=nil&&len(response.TLS.VerifiedChains)>0
  out.TLSVerified=&verified
  if !verified{out.Status="tls_error";out.ErrorCode="tls_verification_failed";return out}
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
 switch{
 case out.Checked==0:out.Status="not_checked"
 case out.FailureCount>0&&out.SuccessCount>0:out.Status="partial_failure"
 case out.FailureCount>0:out.Status="failed"
 case out.Truncated||out.Checked<out.TotalResolved:out.Status="incomplete"
 default:out.Status="reachable"
 }
 return out
}

// compile-time assertions pin references to the certificate errors used by
// Go's verified TLS transport rather than resorting to InsecureSkipVerify.
var _ = x509.HostnameError{}
