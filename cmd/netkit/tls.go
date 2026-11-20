package main

import (
 "context"
 "crypto/tls"
 "crypto/x509"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "net"
 "strings"
 "time"
)

type TLSReport struct {
 Host string `json:"host"`
 Port int `json:"port"`
 Connected bool `json:"connected"`
 Verified bool `json:"verified"`
 TLSVersion string `json:"tls_version,omitempty"`
 CipherSuite string `json:"cipher_suite,omitempty"`
 ALPN string `json:"alpn,omitempty"`
 Subject string `json:"subject,omitempty"`
 Issuer string `json:"issuer,omitempty"`
 DNSNames []string `json:"dns_names,omitempty"`
 IPAddresses []string `json:"ip_addresses,omitempty"`
 NotBefore string `json:"not_before,omitempty"`
 NotAfter string `json:"not_after,omitempty"`
 DaysRemaining int `json:"days_remaining"`
 ChainLength int `json:"chain_length,omitempty"`
 DurationMS int64 `json:"duration_ms"`
 VerificationError string `json:"verification_error,omitempty"`
 ConnectionError string `json:"connection_error,omitempty"`
 VerificationCode string `json:"verification_code,omitempty"`
 ConnectionCode string `json:"connection_code,omitempty"`
}

// Stable classifications preserve raw Go errors for diagnostics and JSON consumers.
// A certificate may have multiple problems; the primary code uses validity,
// then hostname, authority, usage, and finally other certificate errors.
func classifyTLSVerification(err error,leaf *x509.Certificate,now time.Time)string{
 if err==nil{return ""}
 if leaf!=nil{
  if now.Before(leaf.NotBefore){return "cert_not_yet_valid"}
  if now.After(leaf.NotAfter){return "cert_expired"}
 }
 var hostnameErr x509.HostnameError
 if errors.As(err,&hostnameErr){return "hostname_mismatch"}
 var unknownCA x509.UnknownAuthorityError
 if errors.As(err,&unknownCA){return "untrusted_authority"}
 var invalid x509.CertificateInvalidError
 if errors.As(err,&invalid){
  switch invalid.Reason {
  case x509.Expired:
   if leaf!=nil && now.Before(leaf.NotBefore){return "cert_not_yet_valid"}
   return "cert_expired"
  case x509.IncompatibleUsage:return "invalid_key_usage"
  default:return "invalid_certificate"
  }
 }
 var rootsErr x509.SystemRootsError
 if errors.As(err,&rootsErr){return "system_roots_error"}
 return "certificate_verification_failed"
}
func classifyTLSConnection(err error)string{
 if err==nil{return ""}
 var networkErr net.Error
 if errors.As(err,&networkErr)&&networkErr.Timeout(){return "timeout"}
 if errors.Is(err,context.DeadlineExceeded){return "timeout"}
 var recordErr tls.RecordHeaderError
 if errors.As(err,&recordErr){return "tls_handshake_failed"}
 var opErr *net.OpError
 if errors.As(err,&opErr){
  if opErr.Op=="dial"{return "tcp_connect_failed"}
  // Post-connect TLS read/write failures may surface as net.OpError.
  return "tls_handshake_failed"
 }
 return "tls_handshake_failed"
}
func tlsVersionName(version uint16)string{
 switch version {
 case tls.VersionTLS10:return "TLS 1.0"
 case tls.VersionTLS11:return "TLS 1.1"
 case tls.VersionTLS12:return "TLS 1.2"
 case tls.VersionTLS13:return "TLS 1.3"
 default:return fmt.Sprintf("0x%x",version)
 }
}

// A diagnostic-only handshake collects the peer certificate even when it is
// expired or untrusted. No application data is sent. The certificate is then
// verified explicitly with system trust roots, correct hostname and intermediates.
func inspectTLS(host string,port int,timeout time.Duration)(report TLSReport){
 report=TLSReport{Host:host,Port:port}
 started:=time.Now()
 defer func(){report.DurationMS=time.Since(started).Milliseconds()}()
 address:=net.JoinHostPort(host,fmt.Sprint(port))
 dialer:=&net.Dialer{Timeout:timeout}
 connection,err:=tls.DialWithDialer(dialer,"tcp",address,&tls.Config{
  ServerName:host,
  InsecureSkipVerify:true, // Intentional diagnostics; x509.Verify below.
  MinVersion:tls.VersionTLS10,
 })
 if err!=nil{report.ConnectionError=err.Error();report.ConnectionCode=classifyTLSConnection(err);return report}
 defer connection.Close()
 state:=connection.ConnectionState()
 report.Connected=true
 report.TLSVersion=tlsVersionName(state.Version)
 report.CipherSuite=tls.CipherSuiteName(state.CipherSuite)
 report.ALPN=state.NegotiatedProtocol
 report.ChainLength=len(state.PeerCertificates)
 if len(state.PeerCertificates)==0{
  report.VerificationError="no peer certificate"
  report.VerificationCode="no_peer_certificate"
  return report
 }
 leaf:=state.PeerCertificates[0]
 report.Subject=leaf.Subject.String()
 report.Issuer=leaf.Issuer.String()
 report.DNSNames=append([]string{},leaf.DNSNames...)
 for _,ip:=range leaf.IPAddresses {report.IPAddresses=append(report.IPAddresses,ip.String())}
 report.NotBefore=leaf.NotBefore.UTC().Format(time.RFC3339)
 report.NotAfter=leaf.NotAfter.UTC().Format(time.RFC3339)
 report.DaysRemaining=int(time.Until(leaf.NotAfter).Hours()/24)
 roots,err:=x509.SystemCertPool()
 if err!=nil{
  report.VerificationError="system trust store: "+err.Error()
  report.VerificationCode="system_roots_error"
  return report
 }
 if roots==nil {roots=x509.NewCertPool()}
 intermediates:=x509.NewCertPool()
 for _,cert:=range state.PeerCertificates[1:]{intermediates.AddCert(cert)}
 _,err=leaf.Verify(x509.VerifyOptions{
  DNSName:host,
  Roots:roots,
  Intermediates:intermediates,
  CurrentTime:time.Now(),
  KeyUsages:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
 })
 if err!=nil {report.VerificationError=err.Error();report.VerificationCode=classifyTLSVerification(err,leaf,time.Now());return report}
 report.Verified=true
 return report
}

func validTLSTarget(host string)bool{
 if host==""||strings.ContainsAny(host,"/@\\ \t\n"){return false}
 if net.ParseIP(host)!=nil {return true}
 return validDomain(host)
}
func tlsHelp(){
 fmt.Println("用法: netkit tls [-port 443] [-timeout 5s] [--output text|json] [-lang zh|en] HOST")
 fmt.Println("示例: netkit tls example.com")
 fmt.Println("      netkit tls -port 8443 --output json example.com")
 fmt.Println("说明: 分别报告 TLS 握手与系统信任链/主机名验证结果，不绕过验证结论")
}
func runTLS(args []string)error{
 if len(args)==0||args[0]=="-h"||args[0]=="--help"{tlsHelp();return nil}
 fs:=flag.NewFlagSet("tls",flag.ContinueOnError)
 port:=fs.Int("port",443,"TLS port")
 timeout:=fs.Duration("timeout",5*time.Second,"connection timeout")
 output:=fs.String("output","text","text or json")
 lang:=fs.String("lang","zh","zh or en")
 if err:=fs.Parse(args);err!=nil{return err}
 if *port<1||*port>65535{return errors.New("-port must be between 1 and 65535")}
 if *timeout<=0{return errors.New("-timeout must be positive")}
 if *lang!="zh"&&*lang!="en"{return errors.New("-lang must be zh or en")}
 format,err:=resolveOutputFormat(*output,false)
 if err!=nil{return err}
 if fs.NArg()!=1||!validTLSTarget(fs.Arg(0)){return fmt.Errorf("expected one valid hostname or IP")}
 report:=inspectTLS(strings.TrimSuffix(fs.Arg(0),"."),*port,*timeout)
 if format=="json"{
  b,err:=json.MarshalIndent(report,"","  ")
  if err!=nil{return err}
  fmt.Println(string(b))
 }else{
  name:=func(zh,en string)string{if *lang=="en"{return en};return zh}
  fmt.Printf("%s: %s:%d\n",name("TLS 目标","TLS target"),report.Host,report.Port)
  if !report.Connected{
   fmt.Printf("  %s: %s\n",name("连接失败","Connection failed"),report.ConnectionError)
   if report.ConnectionCode!=""{fmt.Printf("  %s: %s\n",name("错误类型","Error code"),report.ConnectionCode)}
  }else{
   fmt.Printf("  %s: %s | %s | %s: %dms\n",name("握手成功","Handshake OK"),report.TLSVersion,report.CipherSuite,name("耗时","Duration"),report.DurationMS)
   if report.ALPN!=""{fmt.Printf("  ALPN: %s\n",report.ALPN)}
   fmt.Printf("  %s: %s\n",name("证书主题","Subject"),report.Subject)
   fmt.Printf("  %s: %s\n",name("颁发者","Issuer"),report.Issuer)
   fmt.Printf("  %s: %s\n",name("到期时间","Expires"),report.NotAfter)
   fmt.Printf("  %s: %d\n",name("剩余天数","Days remaining"),report.DaysRemaining)
   fmt.Printf("  %s: %t\n",name("证书有效","Certificate verified"),report.Verified)
   if report.VerificationCode!=""{fmt.Printf("  %s: %s\n",name("验证类型","Verification code"),report.VerificationCode)}
   if report.VerificationError!=""{fmt.Printf("  %s: %s\n",name("验证错误","Verification error"),report.VerificationError)}
  }
 }
 if !report.Connected||!report.Verified{return fmt.Errorf("TLS connection or certificate verification failed")}
 return nil
}

