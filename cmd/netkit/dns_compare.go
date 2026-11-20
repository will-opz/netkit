package main

import (
 "context"
 "encoding/json"
 "fmt"
 "net"
 "sort"
 "strings"
 "sync"
 "time"
)

type DNSResolverResult struct {
 Name string `json:"name"`
 Server string `json:"server,omitempty"`
 A []string `json:"a,omitempty"`
 AAAA []string `json:"aaaa,omitempty"`
 CNAME string `json:"cname,omitempty"`
 DurationMS int64 `json:"duration_ms"`
 Error string `json:"error,omitempty"`
}
type DNSCompareReport struct {
 Domain string `json:"domain"`
 Resolvers []DNSResolverResult `json:"resolvers"`
 Different bool `json:"different"`
 Detail *DNSCompareDetail `json:"detail,omitempty"`
}

func newDNSResolver(server string)*net.Resolver {
 if server=="" {return net.DefaultResolver}
 return &net.Resolver{PreferGo:true,Dial:func(ctx context.Context,network,address string)(net.Conn,error){
  // The resolver selects UDP and retries over TCP for truncated responses.
  return (&net.Dialer{}).DialContext(ctx,network,server)
 }}
}
func uniqueSorted(values []string)[]string{
 seen:=map[string]bool{}
 result:=[]string{}
 for _,v:=range values {
  if !seen[v]{seen[v]=true;result=append(result,v)}
 }
 sort.Strings(result)
 return result
}
func lookupDNSWithResolver(ctx context.Context,resolver *net.Resolver,name string)DNSResolverResult {
 result:=DNSResolverResult{}
 ips,err:=resolver.LookupIPAddr(ctx,name)
 if err!=nil{result.Error=err.Error()} else {
  for _,ip:=range ips{
   if ip.IP.To4()!=nil{result.A=append(result.A,ip.IP.String())
   }else{result.AAAA=append(result.AAAA,ip.IP.String())}
  }
  result.A=uniqueSorted(result.A)
  result.AAAA=uniqueSorted(result.AAAA)
 }
 cname,err:=resolver.LookupCNAME(ctx,name)
 if err==nil{
  cname=strings.TrimSuffix(cname,".")
  if !strings.EqualFold(cname,name) {result.CNAME=cname}
 }
 return result
}
func compareDNSResolvers(domain string,timeout time.Duration)DNSCompareReport {
 entries:=[]DNSResolverResult{
  {Name:"System"},
  {Name:"Cloudflare",Server:"1.1.1.1:53"},
  {Name:"Google",Server:"8.8.8.8:53"},
 }
 var wg sync.WaitGroup
 for i:=range entries{
  wg.Add(1)
  go func(index int){
   defer wg.Done()
   start:=time.Now()
   ctx,cancel:=context.WithTimeout(context.Background(),timeout)
   defer cancel()
   current:=entries[index]
   result:=lookupDNSWithResolver(ctx,newDNSResolver(current.Server),domain)
   result.Name=current.Name
   result.Server=current.Server
   result.DurationMS=time.Since(start).Milliseconds()
   entries[index]=result
  }(i)
 }
 wg.Wait()
 compared:=false
 signature:=""
 different:=false
 for _,entry:=range entries{
  if entry.Error!=""{continue}
  current:=strings.Join(entry.A,",")+"|"+strings.Join(entry.AAAA,",")
  if !compared {signature=current;compared=true
  }else if current!=signature {different=true}
 }
 return DNSCompareReport{Domain:domain,Resolvers:entries,Different:different}
}
func runDNSCompare(name string,timeout time.Duration,format,lang string,details bool,recordType string)error {
 if !validDomain(name) {return fmt.Errorf("invalid domain %q",name)}
 if timeout<=0{return fmt.Errorf("timeout must be positive")}
 report:=compareDNSResolvers(strings.TrimSuffix(strings.ToLower(name),"."),timeout)
 if details{
  recordType=strings.ToUpper(strings.TrimSpace(recordType))
  if _,ok:=supportedDNSTypes[recordType];!ok{return fmt.Errorf("unsupported DNS record type %q",recordType)}
  addDNSCompareDetail(&report,report.Domain,recordType,timeout)
 }
 if format=="json" {
  b,err:=json.MarshalIndent(report,"","  ")
  if err!=nil{return err}
  fmt.Println(string(b))
  return nil
 }
 label:="DNS 解析器对比"
 if lang=="en"{label="DNS resolver comparison"}
 fmt.Printf("%s: %s\n",label,report.Domain)
 for _,res:=range report.Resolvers{
  fmt.Printf("  %s",res.Name)
  if res.Server!=""{fmt.Printf(" (%s)",res.Server)}
  fmt.Printf(" | %dms\n",res.DurationMS)
  for _,ip:=range res.A{fmt.Println("    A     ",ip)}
  for _,ip:=range res.AAAA{fmt.Println("    AAAA  ",ip)}
  if res.CNAME!=""{fmt.Println("    CNAME ",res.CNAME)}
  if res.Error!=""{fmt.Println("    Error ",res.Error)}
 }
 if report.Detail!=nil {fmt.Print(formatDNSCompareDetail(*report.Detail,lang))}
 if report.Different{
  if lang=="en"{fmt.Println("A/AAAA responses differ (this can be normal for CDN/GeoDNS).")
  }else{fmt.Println("A/AAAA 结果存在差异（CDN/GeoDNS 场景可能是正常现象）。")}
 }
 return nil
}
