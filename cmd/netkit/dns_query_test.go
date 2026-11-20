package main

import (
 "context"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)

func TestDNSRCODEAndTypeNames(t *testing.T){
 for _,tc:=range []struct{code int;want string}{{0,"NOERROR"},{2,"SERVFAIL"},{3,"NXDOMAIN"},{5,"REFUSED"},{99,"UNKNOWN(99)"}}{
  if got:=dnsRCODEName(tc.code);got!=tc.want{t.Fatalf("RCODE %d: %s",tc.code,got)}
 }
 for _,tc:=range []struct{code int;want string}{{6,"SOA"},{33,"SRV"},{257,"CAA"},{16,"TXT"},{999,"TYPE999"}}{
  if got:=dnsTypeName(tc.code);got!=tc.want{t.Fatalf("type %d: %s",tc.code,got)}
 }
}
func TestDNSQueryResponseRecords(t *testing.T){
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.URL.Query().Get("name")!="example.com"||r.URL.Query().Get("type")!="SOA"{
   t.Errorf("bad DoH query: %s",r.URL.String())
  }
  if got:=r.Header.Get("Accept");got!="application/dns-json"{t.Errorf("accept: %s",got)}
  w.Header().Set("Content-Type","application/dns-json")
  w.Write([]byte(`{
    "Status":0,"TC":false,"AD":true,"CD":false,
    "Answer":[{"name":"example.com.","type":6,"TTL":3600,"data":"ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 300"}],
    "Authority":[{"name":"example.com.","type":2,"TTL":172800,"data":"ns1.example.com."}]
  }`))
 }))
 defer server.Close()
 r:=performDNSQuery(context.Background(),server.Client(),server.URL,"Test","example.com","SOA")
 if r.Error!=""||r.RCODE!=0||r.Status!="NOERROR"||!r.AuthenticData||r.CheckingDisabled||len(r.Answers)!=1||len(r.Authority)!=1 {
  t.Fatalf("bad response: %+v",r)
 }
 if r.Answers[0].TTL!=3600||r.Answers[0].Type!="SOA"||r.Authority[0].TTL!=172800 {
  t.Fatalf("TTL/authority lost: %+v",r)
 }
 if r.DurationMS<0 {t.Fatalf("negative latency: %+v",r)}
}
func TestDNSQueryNegativeRCODEAndNoData(t *testing.T){
 for _,tc:=range []struct{status int;want string}{
  {3,"NXDOMAIN"},{2,"SERVFAIL"},{5,"REFUSED"},{0,"NOERROR"},
 }{
  server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
   w.Header().Set("Content-Type","application/dns-json")
   w.Write([]byte(`{"Status":`+stringCode(tc.status)+`,"Authority":[{"name":"example.com.","type":6,"TTL":300,"data":"soa"}]}`))
  }))
  r:=performDNSQuery(context.Background(),server.Client(),server.URL,"Test","missing.example.com","A")
  server.Close()
  if r.Error!=""||r.Status!=tc.want||len(r.Answers)!=0||len(r.Authority)!=1 {
   t.Fatalf("status %d: %+v",tc.status,r)
  }
 }
}
func stringCode(i int)string{
 switch i{case 0:return "0";case 2:return "2";case 3:return "3";case 5:return "5"}
 return "99"
}
func TestDNSQueryRecordVariations(t *testing.T){
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Content-Type","application/dns-json")
  w.Write([]byte(`{"Status":0,"Answer":[
   {"name":"example.com.","type":257,"TTL":600,"data":"0 issue \\"letsencrypt.org\\""},
   {"name":"_sip._tcp.example.com.","type":33,"TTL":120,"data":"10 5 5060 sip.example.com."}
  ]}`))
 }))
 defer server.Close()
 r:=performDNSQuery(context.Background(),server.Client(),server.URL,"Test","example.com","CAA")
 if r.Error!=""||len(r.Answers)!=2||r.Answers[0].Type!="CAA"||r.Answers[1].Type!="SRV"||r.Answers[1].TTL!=120{
  t.Fatalf("CAA/SRV: %+v",r)
 }
}
func TestDNSQueryFailureClassification(t *testing.T){
 cases:=[]struct{code int;body string;needle string}{
  {502,"upstream unavailable","DoH HTTP 502"},
  {200,`{}`,"invalid DNS RCODE"},
  {200,`not-json`,"invalid DoH JSON"},
 }
 for _,tc:=range cases{
  srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
   w.WriteHeader(tc.code);w.Write([]byte(tc.body))
  }))
  r:=performDNSQuery(context.Background(),srv.Client(),srv.URL,"Test","example.com","A")
  srv.Close()
  if !strings.Contains(r.Error,tc.needle)||r.RCODE!=-1{
   t.Fatalf("expected %q: %+v",tc.needle,r)
  }
 }
}
func TestDNSQueryInputValidation(t *testing.T){
 for _,name:=range []string{"example.com","_dmarc.example.com","_sip._tcp.example.com"}{
  if !validDNSQueryName(name){t.Fatalf("rejected %s",name)}
 }
 for _,name:=range []string{"example","http://example.com","bad!.example.com","_bad!.example.com","_sip._tcp.example.123","_example.com","_sip..example.com"}{
  if validDNSQueryName(name){t.Fatalf("accepted %s",name)}
 }
 _,_,err:=dohProviderEndpoint("unsupported")
 if err==nil{t.Fatal("unrecognized DoH service must fail")}
 if _,ok:=supportedDNSTypes["SOA"];!ok{t.Fatal("SOA missing")}
 if _,ok:=supportedDNSTypes["CAA"];!ok{t.Fatal("CAA missing")}
 if _,ok:=supportedDNSTypes["SRV"];!ok{t.Fatal("SRV missing")}
 if _,err:=executeDNSQuery("not-a-domain","A","cloudflare",time.Second,http.DefaultClient);err==nil{t.Fatal("invalid domain accepted")}
 if _,err:=executeDNSQuery("example.com","BAD","cloudflare",time.Second,http.DefaultClient);err==nil{t.Fatal("invalid query type accepted")}
}
func TestDNSQueryCancelledContext(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 r:=performDNSQuery(ctx,http.DefaultClient,"http://127.0.0.1:1","Test","example.com","A")
 if r.Error=="" {t.Fatalf("expected cancellation failure: %+v",r)}
}
