package main

import (
 "context"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "net"
 "net/http"
 "os"
 "strings"
 "sync"
 "time"
 "unicode"
)

type DomainReport struct {
 Domain string `json:"domain"`
 A []string `json:"a,omitempty"`
 AAAA []string `json:"aaaa,omitempty"`
 CNAME string `json:"cname,omitempty"`
 MX []string `json:"mx,omitempty"`
 NS []string `json:"ns,omitempty"`
 TXT []string `json:"txt,omitempty"`
 Websites []WebsiteCheck `json:"websites,omitempty"`
 Registration *DomainRegistration `json:"registration,omitempty"`
 Errors map[string]string `json:"errors,omitempty"`
}

// This first version accepts ASCII/Punycode DNS hostnames, not URLs, email
// addresses, wildcard queries, or IP literals. The trailing dot is optional.
func validDomain(raw string)bool {
 d:=strings.TrimSuffix(raw,".")
 if len(d)<3||len(d)>253||strings.ContainsAny(d,":/@\\ \t\n"){return false}
 if net.ParseIP(d)!=nil {return false}
 labels:=strings.Split(d,".")
 if len(labels)<2{return false}
 for _,label:=range labels {
  if len(label)==0||len(label)>63||label[0]=='-'||label[len(label)-1]=='-' {return false}
  for _,r:=range label {
   if r>unicode.MaxASCII||!(unicode.IsLetter(r)||unicode.IsDigit(r)||r=='-'){return false}
  }
 }
 tld:=labels[len(labels)-1]
 if len(tld)<2{return false}
 numeric:=true
 for _,r:=range tld{if r<'0'||r>'9'{numeric=false;break}}
 return !numeric
}
func isOptionalRecordMissing(kind string,err error)bool{
 if kind=="A/AAAA" {return false}
 var dnsErr *net.DNSError
 return errors.As(err,&dnsErr)&&dnsErr.IsNotFound
}
func queryDomain(domain string,timeout time.Duration)DomainReport{
 report:=DomainReport{Domain:strings.TrimSuffix(strings.ToLower(domain),"."),Errors:map[string]string{}}
 resolver:=net.DefaultResolver
 var wg sync.WaitGroup
 run:=func(kind string,fn func(context.Context)error){
  wg.Add(1)
  go func(){defer wg.Done()
   ctx,cancel:=context.WithTimeout(context.Background(),timeout)
   defer cancel()
   if err:=fn(ctx);err!=nil {
    // Errors map is shared; serialize writes by a mutex.
    if isOptionalRecordMissing(kind,err) {return}
    domainErrorMu.Lock();report.Errors[kind]=err.Error();domainErrorMu.Unlock()
   }
  }()
 }
 run("A/AAAA",func(ctx context.Context)error{
  ips,err:=resolver.LookupIPAddr(ctx,report.Domain)
  if err!=nil{return err}
  for _,ip:=range ips{
   if ip.IP.To4()!=nil{report.A=append(report.A,ip.IP.String())
   }else{report.AAAA=append(report.AAAA,ip.IP.String())}
  }
  return nil
 })
 run("CNAME",func(ctx context.Context)error{
  x,err:=resolver.LookupCNAME(ctx,report.Domain)
  if err!=nil{return err}
  x=strings.TrimSuffix(x,".")
  if !strings.EqualFold(x,report.Domain){report.CNAME=x}
  return nil
 })
 run("MX",func(ctx context.Context)error{
  xs,err:=resolver.LookupMX(ctx,report.Domain)
  if err!=nil{return err}
  for _,x:=range xs{report.MX=append(report.MX,fmt.Sprintf("%d %s",x.Pref,strings.TrimSuffix(x.Host,".")))}
  return nil
 })
 run("NS",func(ctx context.Context)error{
  xs,err:=resolver.LookupNS(ctx,report.Domain)
  if err!=nil{return err}
  for _,x:=range xs{report.NS=append(report.NS,strings.TrimSuffix(x.Host,"."))}
  return nil
 })
 run("TXT",func(ctx context.Context)error{
  xs,err:=resolver.LookupTXT(ctx,report.Domain)
  if err!=nil{return err}
  for _,x:=range xs{
   if len(x)>500 {x=x[:500]+"…"}
   report.TXT=append(report.TXT,x)
  }
  return nil
 })
 wg.Wait()
 if len(report.Errors)==0 {report.Errors=nil}
 return report
}
var domainErrorMu sync.Mutex

func domainHelp(){
 fmt.Println("用法: netkit domain [选项] <domain>")
 fmt.Println("      netkit domain records [选项] <domain>")
 fmt.Println("默认: 注册信息 + 主域名/www 的 CDN 与网站访问检测；显式子域名仅检查该主机")
 fmt.Println("records: 输出 A / AAAA / CNAME / MX / NS / TXT 原始 DNS 记录")
 fmt.Println("选项: --output text|json  -lang zh|en  -timeout 5s  -no-rdap")
 fmt.Println("示例: netkit baidu.com")
 fmt.Println("      netkit domain records baidu.com")
}
func runDomain(args []string)error{
 if len(args)==0||args[0]=="-h"||args[0]=="--help"{domainHelp();return nil}
 records:=false
 if args[0]=="records"{records=true;args=args[1:]}
 fs:=flag.NewFlagSet("domain",flag.ContinueOnError)
 output:=fs.String("output","text","text/json")
 lang:=fs.String("lang","zh","zh/en")
 timeout:=fs.Duration("timeout",5*time.Second,"query timeout")
 noRDAP:=fs.Bool("no-rdap",false,"skip domain registration RDAP query")
 if err:=fs.Parse(args);err!=nil{return err}
 remaining:=fs.Args()
 if len(remaining)>0&&remaining[0]=="records" {records=true;remaining=remaining[1:]}
 if *lang!="zh"&&*lang!="en"{return fmt.Errorf("lang must be zh or en")}
 if *timeout<=0{return fmt.Errorf("timeout must be positive")}
 format,err:=resolveOutputFormat(*output,false);if err!=nil{return err}
 if len(remaining)!=1||!validDomain(remaining[0]){
  return fmt.Errorf("expected one valid ASCII domain, got %q",strings.Join(remaining," "))
 }
 name:=strings.TrimSuffix(strings.ToLower(remaining[0]),".")
 if records {
  r:=queryDomain(name,*timeout)
  if format=="json"{b,_:=json.MarshalIndent(r,"","  ");fmt.Println(string(b));return nil}
  fmt.Printf("%s: %s\n",map[bool]string{true:"域名 DNS 记录",false:"Domain DNS records"}[*lang=="zh"],r.Domain)
  printEntries:=func(kind string,values []string){
   for _,value:=range values{fmt.Printf("  %-6s %s\n",kind,value)}
  }
  printEntries("A",r.A);printEntries("AAAA",r.AAAA)
  if r.CNAME!=""{printEntries("CNAME",[]string{r.CNAME})}
  printEntries("MX",r.MX);printEntries("NS",r.NS);printEntries("TXT",r.TXT)
  if len(r.Errors)>0 {
   fmt.Fprintln(os.Stderr,"DNS 部分记录不可用 / some lookups failed:")
   for key,e:=range r.Errors{fmt.Fprintln(os.Stderr," ",key,":",e)}
  }
  return nil
 }
 result:=DomainReport{Domain:name}
 var registration DomainRegistration
 var wg sync.WaitGroup
 wg.Add(1)
 go func(){defer wg.Done();result.Websites=inspectWebsites(name,*timeout)}()
 if !*noRDAP {
  wg.Add(1)
  go func(){
   defer wg.Done()
   registration=fetchDomainRegistration(&http.Client{Timeout:3*(*timeout)},name,*timeout)
  }()
 }
 wg.Wait()
 if !*noRDAP{result.Registration=&registration}
 if format=="json"{b,_:=json.MarshalIndent(result,"","  ");fmt.Println(string(b));return nil}
 label:="域名";if *lang=="en"{label="Domain"}
 fmt.Printf("%s: %s\n",label,result.Domain)
 heading:="网站检测";if *lang=="en"{heading="Website checks"}
 fmt.Println(heading+":")
 fmt.Print(formatWebsiteReport(result.Websites,*lang))
 if result.Registration!=nil{fmt.Print(formatDomainRegistration(*result.Registration,*lang))}
 return nil
}

func formatDomainRegistration(r DomainRegistration,lang string)string{
 label:=func(zh,en string)string{if lang=="en"{return en};return zh}
 var b strings.Builder
 fmt.Fprintf(&b,"\n%s (RDAP)\n",label("域名注册信息","Domain registration"))
 if r.Error!=""{
  fmt.Fprintf(&b,"  %s: %s\n",label("查询失败","Lookup failed"),r.Error)
  return b.String()
 }
 fields:=[][2]string{
  {label("注册域名","Registered domain"),r.Domain},
  {label("注册商","Registrar"),r.Registrar},
  {label("注册商 IANA ID","Registrar IANA ID"),r.RegistrarIANAID},
  {label("注册时间","Created"),r.CreatedAt},
  {label("更新时间","Updated"),r.UpdatedAt},
  {label("到期时间","Expires"),r.ExpiresAt},
  {label("域名状态","Status"),strings.Join(r.Status,", ")},
 }
 for _,item:=range fields{if item[1]!=""{fmt.Fprintf(&b,"  %s: %s\n",item[0],item[1])}}
 return b.String()
}
