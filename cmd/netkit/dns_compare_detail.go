package main

import (
 "context"
 "net/http"
 "strconv"
 "sort"
 "strings"
 "sync"
 "time"
)

// DNSCompareDetail deliberately separates system-resolution observations
// (which Go's net.Resolver cannot expose raw RCODE/TTL for) from public DoH
// observations. Failure from one provider must not erase the others.
type DNSCompareDetail struct {
 Type string `json:"type"`
 Providers []DNSQueryReport `json:"providers"`
 RCODEDifferent bool `json:"rcode_different"`
 AnswerDifferent bool `json:"answer_different"`
 TTLDifferent bool `json:"ttl_different"`
}

func dnsAnswerSignature(report DNSQueryReport)string{
 if report.Error!="" {return ""}
 items:=make([]string,0,len(report.Answers))
 for _,record:=range report.Answers{
  items=append(items,strings.ToLower(record.Name)+"|"+record.Type+"|"+strings.ToLower(strings.TrimSpace(record.Data)))
 }
 sort.Strings(items)
 return strings.Join(items,"\n")
}
func dnsTTLSignature(report DNSQueryReport)string{
 if report.Error!="" {return ""}
 items:=make([]string,0,len(report.Answers))
 for _,record:=range report.Answers{
  items=append(items,strings.ToLower(record.Name)+"|"+record.Type+"|"+strings.ToLower(strings.TrimSpace(record.Data))+"|"+strconv.FormatUint(uint64(record.TTL),10))
 }
 sort.Strings(items)
 return strings.Join(items,"\n")
}
func compareDNSDetailReports(recordType string,results []DNSQueryReport)DNSCompareDetail{
 detail:=DNSCompareDetail{Type:recordType,Providers:results}
 var reference *DNSQueryReport
 for i:=range results{
  r:=&results[i]
  if r.Error!=""||r.RCODE<0{continue}
  if reference==nil{reference=r;continue}
  if r.RCODE!=reference.RCODE{detail.RCODEDifferent=true}
  if dnsAnswerSignature(*r)!=dnsAnswerSignature(*reference){detail.AnswerDifferent=true}
  if !detail.AnswerDifferent && dnsTTLSignature(*r)!=dnsTTLSignature(*reference){detail.TTLDifferent=true}
 }
 return detail
}
func queryDNSCompareDetail(ctx context.Context,domain,recordType string,client *http.Client,endpoints []struct{Name,URL string})DNSCompareDetail{
 results:=make([]DNSQueryReport,len(endpoints))
 var wg sync.WaitGroup
 for i,endpoint:=range endpoints{
  wg.Add(1)
  go func(i int,name,endpoint string){
   defer wg.Done()
   results[i]=performDNSQuery(ctx,client,endpoint,name,domain,recordType)
  }(i,endpoint.Name,endpoint.URL)
 }
 wg.Wait()
 return compareDNSDetailReports(recordType,results)
}
func defaultDNSCompareEndpoints()[]struct{Name,URL string}{
 return []struct{Name,URL string}{
  {"Cloudflare","https://cloudflare-dns.com/dns-query"},
  {"Google","https://dns.google/resolve"},
 }
}
func addDNSCompareDetail(report *DNSCompareReport,domain,recordType string,timeout time.Duration){
 ctx,cancel:=context.WithTimeout(context.Background(),timeout)
 defer cancel()
 client:=&http.Client{Timeout:timeout}
 detail:=queryDNSCompareDetail(ctx,domain,recordType,client,defaultDNSCompareEndpoints())
 report.Detail=&detail
}
