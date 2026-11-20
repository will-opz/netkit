package main

import (
 "context"
 "errors"
 "io"
 "net/http"
 "strings"
 "testing"
)

func TestDomainTargets(t *testing.T){
 cases:=[]struct{name string;want []string}{
  {"baidu.com",[]string{"baidu.com","www.baidu.com"}},
  {"www.baidu.com",[]string{"www.baidu.com"}},
  {"api.baidu.com",[]string{"api.baidu.com"}},
  {"example.co.uk",[]string{"example.co.uk","www.example.co.uk"}},
  {"www.example.co.uk",[]string{"www.example.co.uk"}},
  {"example.com.",[]string{"example.com","www.example.com"}},
 }
 for _,tc:=range cases{
  got:=domainTargets(tc.name)
  if len(got)!=len(tc.want){t.Fatalf("%q: %v",tc.name,got)}
  for i:=range got {if got[i]!=tc.want[i]{t.Fatalf("%q: %v",tc.name,got)}}
 }
}
func TestCDNEvidence(t *testing.T){
 cases:=[]struct{cname string;headers http.Header;provider,confidence string}{
  {"edge.cloudfront.net",nil,"Amazon CloudFront","cname"},
  {"foo.edgekey.net",nil,"Akamai","cname"},
  {"cdn.fastly.net",nil,"Fastly","cname"},
  {"unrelatedcloudfront.net",nil,"","unknown"},
  {"",http.Header{"Server":[]string{"cloudflare"},"Cf-Ray":[]string{"abcd"}},"Cloudflare","headers"},
  {"",http.Header{"X-Amz-Cf-Id":[]string{"id"},"X-Amz-Cf-Pop":[]string{"NRT1"}},"Amazon CloudFront","headers"},
  {"",http.Header{"X-Cache":[]string{"HIT"}},"","unknown"},
  {"test.edgekey.net",http.Header{"Server":[]string{"cloudflare"},"Cf-Ray":[]string{"a"}},"","conflict"},
 }
 for _,tc:=range cases{
  got:=detectCDN(tc.cname,tc.headers)
  if got.Provider!=tc.provider||got.Confidence!=tc.confidence{
   t.Fatalf("%s: %+v expected %s %s",tc.cname,got,tc.provider,tc.confidence)
  }
 }
}
type roundTripFunc func(*http.Request)(*http.Response,error)
func (f roundTripFunc)RoundTrip(req *http.Request)(*http.Response,error){return f(req)}
func responseFor(req *http.Request,status int,header http.Header)*http.Response{
 return &http.Response{StatusCode:status,Header:header,Body:io.NopCloser(strings.NewReader("")),Request:req}
}
func TestWebsiteProbeHTTPSAndStatuses(t *testing.T){
 client:=&http.Client{Transport:roundTripFunc(func(req *http.Request)(*http.Response,error){
  if req.URL.Scheme!="https"{t.Fatal("unexpected HTTP fallback")}
  return responseFor(req,403,http.Header{}),nil
 })}
 got:=probeWebsite(context.Background(),client,"example.com")
 if !got.Reachable||got.Healthy||got.StatusCode!=403||got.URL!="https://example.com/" {
  t.Fatalf("403 should be reachable, restricted: %+v",got)
 }
}
func TestWebsiteProbeHTTPFallback(t *testing.T){
 client:=&http.Client{Transport:roundTripFunc(func(req *http.Request)(*http.Response,error){
  if req.URL.Scheme=="https"{return nil,errors.New("TLS unavailable")}
  return responseFor(req,200,http.Header{}),nil
 })}
 got:=probeWebsite(context.Background(),client,"example.com")
 if !got.Reachable||!got.Healthy||got.URL!="http://example.com/"||got.Error!=""{
  t.Fatalf("unexpected HTTP fallback: %+v",got)
 }
}
func TestWebsiteProbeFailure(t *testing.T){
 client:=&http.Client{Transport:roundTripFunc(func(req *http.Request)(*http.Response,error){
  return nil,errors.New("network unavailable")
 })}
 got:=probeWebsite(context.Background(),client,"example.com")
 if got.Reachable||got.Error=="" {t.Fatalf("unexpected success: %+v",got)}
}
