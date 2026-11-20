package main

import (
 "crypto/tls"
 "crypto/x509"
 "context"
 "errors"
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

func TestTLSVerificationClassification(t *testing.T){
 now:=time.Date(2026,time.November,20,0,0,0,0,time.UTC)
 leaf:=&x509.Certificate{NotBefore:now.Add(-24*time.Hour),NotAfter:now.Add(24*time.Hour)}
 tests:=[]struct{name string;err error;cert *x509.Certificate;want string}{
  {"hostname",x509.HostnameError{Certificate:leaf,Host:"wrong.example"},leaf,"hostname_mismatch"},
  {"untrusted",x509.UnknownAuthorityError{Cert:leaf},leaf,"untrusted_authority"},
  {"invalid usage",x509.CertificateInvalidError{Cert:leaf,Reason:x509.IncompatibleUsage},leaf,"invalid_key_usage"},
  {"other certificate",x509.CertificateInvalidError{Cert:leaf,Reason:x509.NotAuthorizedToSign},leaf,"invalid_certificate"},
  {"other verify",errors.New("unknown verification issue"),leaf,"certificate_verification_failed"},
  {"expired",x509.UnknownAuthorityError{Cert:leaf},&x509.Certificate{NotBefore:now.Add(-48*time.Hour),NotAfter:now.Add(-time.Hour)},"cert_expired"},
  {"not yet valid",x509.UnknownAuthorityError{Cert:leaf},&x509.Certificate{NotBefore:now.Add(time.Hour),NotAfter:now.Add(48*time.Hour)},"cert_not_yet_valid"},
  {"roots",x509.SystemRootsError{Err:errors.New("missing roots")},leaf,"system_roots_error"},
 }
 for _,tc:=range tests{
  t.Run(tc.name,func(t *testing.T){
   if got:=classifyTLSVerification(tc.err,tc.cert,now);got!=tc.want{
    t.Fatalf("got %q want %q",got,tc.want)
   }
  })
 }
 if got:=classifyTLSVerification(nil,leaf,now);got!=""{t.Fatalf("success classified as %s",got)}
}
func TestTLSConnectionClassification(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background());defer cancel()
 if got:=classifyTLSConnection(context.DeadlineExceeded);got!="timeout"{t.Fatalf("deadline: %s",got)}
 if got:=classifyTLSConnection(&net.OpError{Op:"dial",Err:errors.New("connection refused")});got!="tcp_connect_failed"{t.Fatalf("dial: %s",got)}
 if got:=classifyTLSConnection(tls.RecordHeaderError{Msg:"not a TLS server"});got!="tls_handshake_failed"{t.Fatalf("record: %s",got)}
 if got:=classifyTLSConnection(nil);got!=""{t.Fatalf("success classified: %s",got)}
 _=ctx
}
func TestTLSLocalClassificationIntegration(t *testing.T){
 server:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(http.StatusOK)}))
 defer server.Close()
 host,portText,err:=net.SplitHostPort(server.Listener.Addr().String())
 if err!=nil{t.Fatal(err)}
 port,err:=net.LookupPort("tcp",portText)
 if err!=nil{t.Fatal(err)}
 result:=inspectTLS(host,port,3*time.Second)
 if !result.Connected||result.Verified||result.VerificationCode!="untrusted_authority"{
  t.Fatalf("self-signed certificate: %+v",result)
 }
 if result.ConnectionCode!=""{t.Fatalf("handshake succeeded but connection error code set: %+v",result)}
}
