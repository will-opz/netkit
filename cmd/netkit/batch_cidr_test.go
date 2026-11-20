package main

import (
 "strings"
 "testing"
 "net/netip"
 "strconv"
 "time"
)

func TestCIDRIPv4(t *testing.T){
 r,err:=inspectCIDR("192.168.31.158/24","192.168.31.1")
 if err!=nil {t.Fatal(err)}
 if r.Network!="192.168.31.0/24"||r.Mask!="255.255.255.0"||r.Broadcast!="192.168.31.255"||r.UsableHosts!="254"||r.AddressCount!="256"||r.Contains==nil||!*r.Contains {t.Fatalf("wrong IPv4 CIDR: %+v",r)}
 if !strings.Contains(formatCIDR(r,"zh"),"子网掩码") {t.Fatal("missing Chinese label")}
 outside,err:=inspectCIDR("192.168.31.0/24","192.168.32.1")
 if err!=nil||outside.Contains==nil||*outside.Contains {t.Fatalf("false containment: %+v %v",outside,err)}
}
func TestCIDR31And32(t *testing.T){
 for _,prefix:=range []string{"192.0.2.0/31","192.0.2.1/32"}{
  r,err:=inspectCIDR(prefix,"")
  if err!=nil||r.UsableHosts!=r.AddressCount {t.Fatalf("%s: %+v %v",prefix,r,err)}
 }
}
func TestCIDRIPv6(t *testing.T){
 r,err:=inspectCIDR("2001:db8::1/126","2001:db8::3")
 if err!=nil||r.Network!="2001:db8::/126"||r.Last!="2001:db8::3"||r.AddressCount!="4"||r.Broadcast!=""||r.Contains==nil||!*r.Contains {t.Fatalf("IPv6: %+v %v",r,err)}
 wide,err:=inspectCIDR("2001:db8::/32","")
 if err!=nil||wide.AddressCount!="79228162514264337593543950336" {t.Fatalf("IPv6 big int: %+v %v",wide,err)}
}
func TestCIDRBadInputs(t *testing.T){
 for _,tc:=range []struct{cidr,member string}{
  {"invalid",""},{"192.168.1.0/33",""},{"192.168.1.0/24","bad"},
 } {
  if _,err:=inspectCIDR(tc.cidr,tc.member);err==nil {t.Fatalf("accepted invalid %v",tc)}
 }
 if _,err:=netip.ParsePrefix("192.168.1.0/24");err!=nil {t.Fatal(err)}
}
func TestReadIPs(t *testing.T){
 data:="# addresses\n8.8.8.8\n\n2001:4860:4860::8888 # google\n192.168.1.1\n"
 ips,err:=readIPs(strings.NewReader(data),3)
 if err!=nil||len(ips)!=3||ips[1]!="2001:4860:4860::8888" {t.Fatalf("%v, %v",ips,err)}
 if _,err:=readIPs(strings.NewReader(data),2);err==nil {t.Fatal("expected input limit")}
 if _,err:=readIPs(strings.NewReader("1.1.1.1 8.8.8.8\n"),10);err==nil {t.Fatal("expected line format error")}
}
func TestLookupBatchOrderAndLimit(t *testing.T){
 ips:=[]string{"0","1","2","3","4","5","6","7"}
 result:=lookupBatch(ips,2,func(ip string)Result{
  n,_:=strconv.Atoi(ip)
  time.Sleep(time.Duration(8-n)*time.Millisecond)
  return Result{IP:ip}
 })
 for i,r:=range result {if r.IP!=ips[i] {t.Fatalf("index %d: %q",i,r.IP)}}
}

func TestBatchPacingKeepsOrder(t *testing.T){
 ips:=[]string{"1","2","3"}
 result:=lookupBatchPaced(ips,2,time.Millisecond,func(ip string)Result{return Result{IP:ip}})
 for i,r:=range result{if r.IP!=ips[i]{t.Fatalf("result order: %+v",result)}}
}
