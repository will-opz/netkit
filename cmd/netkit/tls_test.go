package main

import (
 "crypto/tls"
 "net"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)

func TestTLSTargetValidation(t *testing.T){
 for _,host:=range []string{"example.com","www.baidu.com","127.0.0.1","2001:db8::1"} {
  if !validTLSTarget(host){t.Fatalf("rejected %q",host)}
 }
 for _,host:=range []string{"","https://example.com","example.com:443","foo@bar.com","-bad.example"}{
  if validTLSTarget(host){t.Fatalf("accepted %q",host)}
 }
}
func TestTLSVersionLabels(t *testing.T){
 if tlsVersionName(tls.VersionTLS13)!="TLS 1.3"||tlsVersionName(tls.VersionTLS12)!="TLS 1.2" {
  t.Fatalf("unexpected version labels")
 }
}
func TestInspectTLSLocalSelfSigned(t *testing.T){
 server:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(http.StatusNoContent)}))
 defer server.Close()
 host,portString,err:=net.SplitHostPort(server.Listener.Addr().String())
 if err!=nil{t.Fatal(err)}
 port,err:=net.LookupPort("tcp",portString)
 if err!=nil{t.Fatal(err)}
 got:=inspectTLS(host,port,3*time.Second)
 if !got.Connected {t.Fatalf("expected successful handshake: %+v",got)}
 if got.Verified {t.Fatalf("self-signed test cert must not pass system root verification: %+v",got)}
 if got.VerificationError=="" {t.Fatalf("expected trust error: %+v",got)}
 if got.NotAfter==""||got.TLSVersion==""||got.Issuer==""||got.ChainLength<1{t.Fatalf("missing certificate fields: %+v",got)}
 if got.DurationMS<0{t.Fatalf("invalid latency: %+v",got)}
 if len(got.IPAddresses)==0 && len(got.DNSNames)==0{t.Fatalf("missing SAN fields: %+v",got)}
}
func TestInspectTLSConnectionFailure(t *testing.T){
 listener,err:=net.Listen("tcp","127.0.0.1:0")
 if err!=nil{t.Fatal(err)}
 address:=listener.Addr().(*net.TCPAddr)
 listener.Close()
 got:=inspectTLS("127.0.0.1",address.Port,300*time.Millisecond)
 if got.Connected||got.ConnectionError=="" {t.Fatalf("expected failed handshake: %+v",got)}
 if strings.Contains(got.ConnectionError,"certificate") {t.Fatalf("network error reported as certificate error: %+v",got)}
}
