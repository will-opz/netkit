package main

import (
 "context"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)

func detailReport(provider string,rcode int,answers []DNSQueryRecord)DNSQueryReport{
 return DNSQueryReport{Provider:provider,RCODE:rcode,Status:dnsRCODEName(rcode),Answers:answers}
}
func TestDNSDetailCompareRCODE(t *testing.T){
 results:=[]DNSQueryReport{
  detailReport("Cloudflare",0,nil),
  detailReport("Google",3,nil),
 }
 got:=compareDNSDetailReports("A",results)
 if !got.RCODEDifferent||got.AnswerDifferent||got.TTLDifferent {t.Fatalf("wrong RCODE comparison: %+v",got)}
}
func TestDNSDetailCompareAnswerOrderAndTTL(t *testing.T){
 a:=DNSQueryRecord{Name:"example.com",Type:"A",TypeCode:1,TTL:300,Data:"192.0.2.10"}
 b:=DNSQueryRecord{Name:"example.com",Type:"A",TypeCode:1,TTL:120,Data:"192.0.2.20"}
 sameValues:=[]DNSQueryReport{
  detailReport("Cloudflare",0,[]DNSQueryRecord{a,b}),
  detailReport("Google",0,[]DNSQueryRecord{b,a}),
 }
 if got:=compareDNSDetailReports("A",sameValues);got.AnswerDifferent||got.TTLDifferent||got.RCODEDifferent{
  t.Fatalf("record order must not count as difference: %+v",got)
 }
 changedTTL:=b;changedTTL.TTL=30
 changed:=[]DNSQueryReport{
  detailReport("Cloudflare",0,[]DNSQueryRecord{a,b}),
  detailReport("Google",0,[]DNSQueryRecord{a,changedTTL}),
 }
 got:=compareDNSDetailReports("A",changed)
 if !got.TTLDifferent||got.AnswerDifferent||got.RCODEDifferent{t.Fatalf("missed TTL-only difference: %+v",got)}
 changedTTL.Data="192.0.2.21"
 changed[1].Answers=[]DNSQueryRecord{a,changedTTL}
 got=compareDNSDetailReports("A",changed)
 if !got.AnswerDifferent{t.Fatalf("missed answer difference: %+v",got)}
}
func TestDNSDetailIgnoresFailedProvider(t *testing.T){
 results:=[]DNSQueryReport{
  detailReport("Cloudflare",0,[]DNSQueryRecord{{Name:"example.com",Type:"A",Data:"192.0.2.1"}}),
  {Provider:"Google",RCODE:-1,Status:"UNKNOWN",Error:"connection timeout"},
 }
 result:=compareDNSDetailReports("A",results)
 if result.RCODEDifferent||result.AnswerDifferent||result.TTLDifferent{t.Fatalf("transport failure is not a disagreement: %+v",result)}
}
func TestDNSDetailHTTPFixturesAndPresentation(t *testing.T){
 a:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.URL.Query().Get("type")!="A"||r.URL.Query().Get("name")!="example.com"{t.Errorf("unexpected query: %s",r.URL.String())}
  w.Header().Set("Content-Type","application/dns-json")
  w.Write([]byte(`{"Status":0,"Answer":[{"name":"example.com.","type":1,"TTL":60,"data":"192.0.2.1"}]}`))
 }))
 defer a.Close()
 b:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Content-Type","application/dns-json")
  w.Write([]byte(`{"Status":0,"Answer":[{"name":"example.com.","type":1,"TTL":120,"data":"192.0.2.1"}]}`))
 }))
 defer b.Close()
 ctx,cancel:=context.WithTimeout(context.Background(),time.Second)
 defer cancel()
 result:=queryDNSCompareDetail(ctx,"example.com","A",http.DefaultClient,[]struct{Name,URL string}{{"Cloudflare",a.URL},{"Google",b.URL}})
 if result.AnswerDifferent||!result.TTLDifferent||result.RCODEDifferent{t.Fatalf("expected TTL difference: %+v",result)}
 out:=formatDNSCompareDetail(result,"zh")
 if !strings.Contains(out,"仅公共解析器")||!strings.Contains(out,"TTL"){t.Fatalf("misleading output: %s",out)}
}
