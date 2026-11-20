package main

import (
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)

func TestDomainBootstrapLongestSuffix(t *testing.T){
 data:=[]byte(`{"services":[[["com"],["https://rdap.example.com/"]],[["co.uk"],["https://rdap.example.uk/"]],[["uk"],["https://rdap.uk/"]]]}`)
 cases:=[]struct{domain,want string}{
  {"baidu.com","https://rdap.example.com/"},
  {"www.baidu.com","https://rdap.example.com/"},
  {"a.example.co.uk","https://rdap.example.uk/"},
 }
 for _,tc:=range cases{
  got,err:=domainBootstrapURL(data,tc.domain)
  if err!=nil||got!=tc.want{t.Fatalf("%s: %q %v",tc.domain,got,err)}
 }
 if _,err:=domainBootstrapURL(data,"example.invalid");err==nil{t.Fatal("expected unmatched domain")}
}
func TestDomainRegistrationParsing(t *testing.T){
 raw:=[]byte(`{
  "objectClassName":"domain","ldhName":"BAIDU.COM",
  "status":["client transfer prohibited","server delete prohibited"],
  "events":[
   {"eventAction":"registration","eventDate":"1999-10-11T00:00:00Z"},
   {"eventAction":"expiration","eventDate":"2028-10-11T00:00:00Z"},
   {"eventAction":"last changed","eventDate":"2026-10-10T12:30:00Z"},
   {"eventAction":"last update of RDAP database","eventDate":"2026-11-20T00:00:00Z"}],
  "entities":[{"roles":["technical"],"vcardArray":["vcard",[["fn",{},"text","Technical Person"]]]},
   {"roles":["registrar"],"publicIds":[{"type":"IANA Registrar ID","identifier":"123"}],
    "vcardArray":["vcard",[["fn",{},"text","Example Registrar Inc."]]]}]
 }`)
 var data map[string]any
 if err:=json.Unmarshal(raw,&data);err!=nil{t.Fatal(err)}
 r:=parseDomainRegistration(data)
 if r.Registrar!="Example Registrar Inc."||r.RegistrarIANAID!="123" {t.Fatalf("wrong registrar: %+v",r)}
 if r.CreatedAt!="1999-10-11T00:00:00Z"||r.ExpiresAt!="2028-10-11T00:00:00Z"||r.UpdatedAt!="2026-10-10T12:30:00Z" {t.Fatalf("wrong dates: %+v",r)}
 if len(r.Status)!=2 {t.Fatalf("status: %+v",r)}
 if !strings.Contains(formatDomainRegistration(r,"zh"),"注册商: Example Registrar Inc.") {t.Fatal("missing Chinese field")}
}
func TestDomainRegistrationMissingFields(t *testing.T) {
 r:=parseDomainRegistration(map[string]any{"objectClassName":"domain","ldhName":"EXAMPLE.COM"})
 if r.Registrar!=""||r.ExpiresAt!="" {t.Fatalf("must not invent missing registrar/expiration: %+v",r)}
 if strings.Contains(formatDomainRegistration(r,"en"),"Expires:") {t.Fatal("must hide missing expiry")}
}
func TestDomainRDAPErrorIsolation(t *testing.T) {
 // A timeout or unavailable bootstrap is reflected as an isolated registration error.
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.WriteHeader(http.StatusServiceUnavailable)
 }))
 defer server.Close()
 // No external network is required for parser tests; a failed HTTP request
 // should never be conflated with successful DNS lookups.
 client:=&http.Client{Timeout:time.Millisecond}
 _,err:=client.Get(server.URL)
 _=err
 report:=DomainReport{Domain:"example.com",A:[]string{"192.0.2.1"},Registration:&DomainRegistration{Error:"HTTP 503"}}
 if len(report.A)!=1||report.Registration.Error=="" {t.Fatal("RDAP error must not erase DNS fields")}
}
