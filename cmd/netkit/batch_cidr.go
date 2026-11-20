package main

import (
 "bufio"
 "encoding/binary"
 "fmt"
 "io"
 "math/big"
 "net/netip"
 "strings"
 "sync"
)

// CIDRReport is offline-only. IPv6 has no broadcast address.
type CIDRReport struct {
 Input string `json:"input"`
 Network string `json:"network"`
 Version int `json:"version"`
 PrefixLength int `json:"prefix_length"`
 AddressCount string `json:"address_count"`
 Mask string `json:"mask,omitempty"`
 First string `json:"first"`
 Last string `json:"last"`
 Broadcast string `json:"broadcast,omitempty"`
 UsableHosts string `json:"usable_hosts,omitempty"`
 Scope string `json:"scope"`
 Contains *bool `json:"contains,omitempty"`
 ContainsIP string `json:"contains_ip,omitempty"`
}

func inspectCIDR(raw,member string)(CIDRReport,error){
 p,err:=netip.ParsePrefix(raw)
 if err!=nil {return CIDRReport{},fmt.Errorf("invalid CIDR %q: %w",raw,err)}
 if p.Addr().Zone()!="" {return CIDRReport{},fmt.Errorf("zone-scoped CIDR not supported")}
 p=p.Masked()
 bits:=128
 version:=6
 if p.Addr().Is4(){bits=32;version=4}
 count:=new(big.Int).Lsh(big.NewInt(1),uint(bits-p.Bits()))
 info:=CIDRReport{Input:raw,Network:p.String(),Version:version,PrefixLength:p.Bits(),AddressCount:count.String(),First:p.Addr().String(),Scope:ipScope(p.Addr().AsSlice())}
 if version==4{
  a:=p.Addr().As4()
  start:=binary.BigEndian.Uint32(a[:])
  mask:=uint32(0)
  if p.Bits()>0 {mask=^uint32(0)<<uint(32-p.Bits())}
  var maskBytes,lastBytes [4]byte
  binary.BigEndian.PutUint32(maskBytes[:],mask)
  binary.BigEndian.PutUint32(lastBytes[:],start|^mask)
  info.Mask=netip.AddrFrom4(maskBytes).String()
  info.Last=netip.AddrFrom4(lastBytes).String()
  info.Broadcast=info.Last
  usable:=new(big.Int).Set(count)
  if p.Bits()<31 {usable.Sub(usable,big.NewInt(2))}
  info.UsableHosts=usable.String()
 }else{
  first:=p.Addr().As16()
  last:=first
  for bit:=p.Bits();bit<128;bit++{last[bit/8]|=1<<uint(7-bit%8)}
  info.Last=netip.AddrFrom16(last).String()
 }
 if member!=""{
  ip,err:=netip.ParseAddr(member)
  if err!=nil||ip.Zone()!="" {return CIDRReport{},fmt.Errorf("invalid member IP %q",member)}
  yes:=p.Contains(ip)
  info.Contains=&yes
  info.ContainsIP=ip.String()
 }
 return info,nil
}

func formatCIDR(info CIDRReport,lang string)string{
 var b strings.Builder
 zh:=lang!="en"
 label:=func(a,c string)string{if zh{return a};return c}
 fmt.Fprintf(&b,"%s: %s\n",label("网段","Network"),info.Network)
 fmt.Fprintf(&b,"%s: IPv%d\n",label("地址类型","IP version"),info.Version)
 fmt.Fprintf(&b,"%s: %s\n",label("地址数量","Addresses"),info.AddressCount)
 fmt.Fprintf(&b,"%s: %s - %s\n",label("地址范围","Range"),info.First,info.Last)
 if info.Mask!="" {fmt.Fprintf(&b,"%s: %s\n",label("子网掩码","Subnet mask"),info.Mask)}
 if info.Version==4 {
  fmt.Fprintf(&b,"%s: %s\n",label("广播地址","Broadcast"),info.Broadcast)
  fmt.Fprintf(&b,"%s: %s\n",label("可用主机数","Usable hosts"),info.UsableHosts)
 }
 fmt.Fprintf(&b,"%s: %s\n",label("地址分类","Scope"),scopeLabel(lang,info.Scope))
 if info.Contains!=nil{
  answer:=label("否","No")
  if *info.Contains {answer=label("是","Yes")}
  fmt.Fprintf(&b,"%s %s: %s\n",label("包含","Contains"),info.ContainsIP,answer)
 }
 return b.String()
}

// readIPs consumes one IP per line. Comments and blank lines are ignored.
// Explicit stdin opt-in prevents accidental blocking in piped environments.
func readIPs(reader io.Reader,maxItems int)([]string,error){
 scanner:=bufio.NewScanner(reader)
 scanner.Buffer(make([]byte,4096),1<<20)
 ips:=[]string{}
 for scanner.Scan(){
  line:=strings.TrimSpace(strings.SplitN(scanner.Text(),"#",2)[0])
  if line=="" {continue}
  if len(strings.Fields(line))!=1{return nil,fmt.Errorf("expected one IP per line: %q",line)}
  ips=append(ips,line)
  if len(ips)>maxItems {return nil,fmt.Errorf("stdin IP count exceeds %d",maxItems)}
 }
 if err:=scanner.Err();err!=nil{return nil,err}
 return ips,nil
}

type batchLookupFn func(string) Result
// Lookup independent addresses in bounded parallelism, preserving input order.
func lookupBatch(ips []string,workers int,fn batchLookupFn)[]Result{
 if workers<1{workers=1}
 if workers>4{workers=4}
 results:=make([]Result,len(ips))
 jobs:=make(chan int)
 var wg sync.WaitGroup
 for i:=0;i<workers;i++{
  wg.Add(1)
  go func(){
   defer wg.Done()
   for index:=range jobs{results[index]=fn(ips[index])}
  }()
 }
 for i:=range ips{jobs<-i}
 close(jobs)
 wg.Wait()
 return results
}
