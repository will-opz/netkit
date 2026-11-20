package main

import (
 "context"
 "errors"
 "io"
 "net/http"
 "strings"
 "testing"
 "time"
)

type httpRoundTrip func(*http.Request)(*http.Response,error)
func (fn httpRoundTrip)RoundTrip(req *http.Request)(*http.Response,error){return fn(req)}
func httpResponse(req *http.Request,code int,location string)*http.Response{
 header:=http.Header{}
 if location!=""{header.Set("Location",location)}
 return &http.Response{StatusCode:code,Header:header,Body:io.NopCloser(strings.NewReader("")),Request:req}
}
func TestHTTPURLValidation(t *testing.T){
 checks:=[]struct{in,want string;fails bool}{
  {"example.com","https://example.com",false},
  {"https://example.com/path","https://example.com/path",false},
  {"http://127.0.0.1:8080/","http://127.0.0.1:8080/",false},
  {"ftp://example.com","",true},
  {"https://user:pass@example.com","",true},
  {"https://example.com/#fragment","",true},
  {"","",true},
 }
 for _,c:=range checks{
  got,err:=normalizeHTTPURL(c.in)
  if (err!=nil)!=c.fails||(!c.fails&&got!=c.want){t.Fatalf("%q: %q %v",c.in,got,err)}
 }
}
func TestHTTPRedirectTraceSuccess(t *testing.T){
 client:=&http.Client{Transport:httpRoundTrip(func(req *http.Request)(*http.Response,error){
  switch req.URL.Path{
  case "/":return httpResponse(req,301,"/next"),nil
  case "/next":return httpResponse(req,302,"https://example.com/final"),nil
  case "/final":return httpResponse(req,200,""),nil
  }
  return httpResponse(req,404,""),nil
 })}
 report:=traceHTTP(context.Background(),client,"https://example.com/",5)
 if report.Status!="ok"||report.Redirects!=2||len(report.Hops)!=3||report.FinalURL!="https://example.com/final"{
  t.Fatalf("unexpected chain: %+v",report)
 }
 if report.Hops[0].Location!="/next"||report.Hops[1].StatusCode!=302{t.Fatalf("missing evidence: %+v",report.Hops)}
}
func TestHTTPLoopAndLimit(t *testing.T){
 client:=&http.Client{Transport:httpRoundTrip(func(req *http.Request)(*http.Response,error){
  if req.URL.Path=="/"{return httpResponse(req,302,"/a"),nil}
  return httpResponse(req,302,"/"),nil
 })}
 loop:=traceHTTP(context.Background(),client,"https://example.com/",5)
 if loop.Status!="redirect_loop"||len(loop.Hops)!=2{t.Fatalf("loop: %+v",loop)}
 limited:=traceHTTP(context.Background(),client,"https://example.com/",1)
 if limited.Status!="redirect_limit"||len(limited.Hops)!=2{t.Fatalf("limit: %+v",limited)}
}
func TestHTTPRestrictionsAndServerErrors(t *testing.T){
 for _,tc:=range []struct{code int;state string}{{200,"ok"},{403,"restricted"},{429,"restricted"},{404,"http_error"},{502,"http_error"}}{
  client:=&http.Client{Transport:httpRoundTrip(func(req *http.Request)(*http.Response,error){
   return httpResponse(req,tc.code,""),nil
  })}
  report:=traceHTTP(context.Background(),client,"https://example.com/",5)
  if report.Status!=tc.state||len(report.Hops)!=1{t.Fatalf("%d: %+v",tc.code,report)}
 }
}
func TestHTTPInvalidRedirectAndDowngrade(t *testing.T){
 client:=&http.Client{Transport:httpRoundTrip(func(req *http.Request)(*http.Response,error){
  if req.URL.Scheme=="https"{return httpResponse(req,301,"http://example.com/"),nil}
  return httpResponse(req,200,""),nil
 })}
 report:=traceHTTP(context.Background(),client,"https://example.com/",3)
 if !report.HTTPSDowngrade||report.Status!="ok"{t.Fatalf("downgrade evidence lost: %+v",report)}
 bad:=&http.Client{Transport:httpRoundTrip(func(req *http.Request)(*http.Response,error){return httpResponse(req,302,"javascript:alert(1)"),nil})}
 r:=traceHTTP(context.Background(),bad,"https://example.com/",5)
 if r.Status!="invalid_redirect"{t.Fatalf("unsafe redirect accepted: %+v",r)}
}
func TestHTTPTimeoutAndNetworkError(t *testing.T){
 client:=&http.Client{Transport:httpRoundTrip(func(req *http.Request)(*http.Response,error){return nil,errors.New("connection refused")})}
 r:=traceHTTP(context.Background(),client,"https://example.com/",5)
 if r.Status!="network_error"||r.Error==""{t.Fatalf("expected network failure: %+v",r)}
 ctx,cancel:=context.WithTimeout(context.Background(),time.Nanosecond)
 defer cancel()
 <-ctx.Done()
 r=traceHTTP(ctx,client,"https://example.com/",5)
 if r.Status!="network_error"{t.Fatalf("expected context cancellation: %+v",r)}
}
