package main

import (
 "reflect"
 "net"
 "errors"
 "strings"
 "testing"
)

func TestSmartRouting(t *testing.T){
 cases:=[]struct{input,want []string}{
  {[]string{"netkit"},[]string{"netkit","ip"}},
  {[]string{"netkit","192.168.1.1"},[]string{"netkit","ip","192.168.1.1"}},
  {[]string{"netkit","8.8.8.8"},[]string{"netkit","ip","8.8.8.8"}},
  {[]string{"netkit","2001:4860:4860::8888"},[]string{"netkit","ip","2001:4860:4860::8888"}},
  {[]string{"netkit","www.baidu.com"},[]string{"netkit","domain","www.baidu.com"}},
  {[]string{"netkit","example.com"},[]string{"netkit","domain","example.com"}},
  {[]string{"netkit","dns"},[]string{"netkit","dns"}},
  {[]string{"netkit","dns","list"},[]string{"netkit","dns","list"}},
  {[]string{"netkit","ip","-all","8.8.8.8"},[]string{"netkit","ip","-all","8.8.8.8"}},
  {[]string{"netkit","-h"},[]string{"netkit","-h"}},
  {[]string{"netkit","--output","json"},[]string{"netkit","ip","--output","json"}},
 }
 for _,c:=range cases {
  got:=defaultCommandArgs(append([]string(nil),c.input...))
  if !reflect.DeepEqual(got,c.want) {t.Errorf("%q -> %q, want %q",c.input,got,c.want)}
 }
}
func TestDomainValidation(t *testing.T){
 valid:=[]string{"www.baidu.com","example.com","foo-bar.example.org","xn--fiqs8s.cn","example.com."}
 invalid:=[]string{"","localhost","192.168.1.1","http://example.com","foo@example.com","a..com","-foo.com","foo-.com","example.123","foo_underscore.com"}
 for _,x:=range valid {if !validDomain(x) {t.Errorf("rejected %q",x)}}
 for _,x:=range invalid {if validDomain(x) {t.Errorf("accepted %q",x)}}
}
func TestResolvConf(t *testing.T){
 raw:="# generated\nnameserver 192.168.31.1\nnameserver 1.1.1.1 # fallback\nsearch lan example.local\noptions timeout:2\n"
 items:=parseResolvConf(raw)
 if len(items)!=1||len(items[0].Nameservers)!=2||items[0].Nameservers[0]!="192.168.31.1"||len(items[0].SearchDomains)!=2 {t.Fatalf("%+v",items)}
}
func TestScutilResolvers(t *testing.T){
 raw:="DNS configuration\nresolver #1\n  nameserver[0] : 192.168.31.1\n  nameserver[1] : 1.1.1.1\n  if_index : 4 (en0)\nresolver #2\n  domain : corp.example\n  nameserver[0] : 10.1.1.1\n  flags : Supplemental\n"
 items:=parseScutilDNS(raw)
 if len(items)!=2||items[0].Nameservers[0]!="192.168.31.1"||items[1].Domain!="corp.example"||!strings.Contains(items[1].Flags,"Supplemental"){t.Fatalf("%+v",items)}
}
func TestPublicDNSServerList(t *testing.T){
 for _,p:=range publicDNS {if p.Name==""||len(p.IPv4)==0||len(p.IPv6)==0 {t.Fatalf("invalid DNS provider: %+v",p)}}
}

func TestOptionalDNSRecordMissing(t *testing.T){
 missing:=&net.DNSError{Err:"no such host",IsNotFound:true}
 if !isOptionalRecordMissing("MX",missing)||!isOptionalRecordMissing("TXT",missing) {t.Fatal("expected missing optional records to be ignored")}
 if isOptionalRecordMissing("A/AAAA",missing) {t.Fatal("missing A/AAAA should remain visible")}
 if isOptionalRecordMissing("MX",errors.New("timeout")) {t.Fatal("unexpected timeout suppression")}
}
