package main

import (
 "context"
 "fmt"
 "net"
 "net/http"
 "net/url"
 "strings"
 "sync"
 "time"
)

// CDNInfo records observable evidence, not a guarantee that every request
// passed through the identified provider.
type CDNInfo struct {
 Provider string `json:"provider,omitempty"`
 Confidence string `json:"confidence"`
 Evidence []string `json:"evidence,omitempty"`
}

type WebsiteCheck struct {
 Host string `json:"host"`
 CNAME string `json:"cname,omitempty"`
 URL string `json:"url,omitempty"`
 FinalURL string `json:"final_url,omitempty"`
 StatusCode int `json:"status_code,omitempty"`
 Reachable bool `json:"reachable"`
 Healthy bool `json:"healthy"`
 LatencyMS int64 `json:"latency_ms,omitempty"`
 TLS bool `json:"tls"`
 CDN CDNInfo `json:"cdn"`
 DNSCDN *CDNInfo `json:"dns_cdn,omitempty"`
 responseHeaders http.Header
 Error string `json:"error,omitempty"`
}

var cdnCNAMEs = []struct{suffix,provider string}{
 {"cloudfront.net","Amazon CloudFront"},
 {"cdn.cloudflare.net","Cloudflare"},
 {"fastly.net","Fastly"},{"fastlylb.net","Fastly"},
 {"akamaiedge.net","Akamai"},{"edgekey.net","Akamai"},
 {"edgesuite.net","Akamai"},{"akamaized.net","Akamai"},
 {"alicdn.com","Alibaba Cloud CDN"},
 {"kunlun.com","Alibaba Cloud CDN"},
}

func knownCDNCNAME(host string)string {
 name:=strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)),".")
 for _,item:=range cdnCNAMEs {
  if name==item.suffix||strings.HasSuffix(name,"."+item.suffix){return item.provider}
 }
 return ""
}

func knownCDNHeaders(headers http.Header) (string,[]string) {
 if headers.Get("CF-Ray")!="" && strings.EqualFold(headers.Get("Server"),"cloudflare"){
  return "Cloudflare",[]string{"HTTP Server: cloudflare","HTTP CF-Ray"}
 }
 if headers.Get("X-Amz-Cf-Id")!="" && headers.Get("X-Amz-Cf-Pop")!=""{
  return "Amazon CloudFront",[]string{"HTTP X-Amz-Cf-Id","HTTP X-Amz-Cf-Pop"}
 }
 if headers.Get("X-Served-By")!="" && headers.Get("X-Cache")!=""{
  return "Fastly",[]string{"HTTP X-Served-By","HTTP X-Cache"}
 }
 return "",nil
}
func detectCDN(cname string,headers http.Header)CDNInfo{
 a:=knownCDNCNAME(cname)
 b,hints:=knownCDNHeaders(headers)
 if a!=""&&b!=""&&a!=b {
  return CDNInfo{Confidence:"conflict",Evidence:append([]string{"CNAME: "+cname+" ("+a+")"},hints...)}
 }
 if a!=""{
  evidence:=[]string{"CNAME: "+cname}
  if b==a{evidence=append(evidence,hints...)}
  return CDNInfo{Provider:a,Confidence:"cname",Evidence:evidence}
 }
 if b!="" {return CDNInfo{Provider:b,Confidence:"headers",Evidence:hints}}
 return CDNInfo{Confidence:"unknown"}
}

func probeWebsite(ctx context.Context,client *http.Client,host string)WebsiteCheck{
 result:=WebsiteCheck{Host:host,CDN:CDNInfo{Confidence:"unknown"}}
 // HTTPS first. HTTP fallback is only used when HTTPS has no HTTP response;
 // 403/404/5xx are reachable responses and must not be hidden.
 urls:=[]string{"https://"+host+"/","http://"+host+"/"}
 for _,endpoint:=range urls{
  req,err:=http.NewRequestWithContext(ctx,http.MethodGet,endpoint,nil)
  if err!=nil{result.Error=err.Error();continue}
  req.Header.Set("User-Agent",agent)
  start:=time.Now()
  response,err:=client.Do(req)
  elapsed:=time.Since(start).Milliseconds()
  if err!=nil {result.Error=err.Error();continue}
  response.Body.Close()
  result.URL=endpoint
  result.FinalURL=response.Request.URL.String()
  result.StatusCode=response.StatusCode
  result.Reachable=true
  result.Healthy=response.StatusCode>=200&&response.StatusCode<400
  result.LatencyMS=elapsed
  result.TLS=response.TLS!=nil
  result.Error=""
  result.responseHeaders=response.Header.Clone()
  result.CDN=detectCDN("",result.responseHeaders)
  break
 }
 return result
}

func checkWebsiteHost(name string,timeout time.Duration) WebsiteCheck{
 ctx,cancel:=context.WithTimeout(context.Background(),2*timeout)
 defer cancel()
 transport:=http.DefaultTransport.(*http.Transport).Clone()
 transport.TLSHandshakeTimeout=timeout
 client:=&http.Client{Transport:transport,Timeout:timeout,CheckRedirect:func(req *http.Request,via []*http.Request)error{
  if len(via)>=5{return fmt.Errorf("too many redirects")}
  // Avoid silently following a redirect to an unrelated host.
  origin:=strings.ToLower(via[0].URL.Hostname())
  dest:=strings.ToLower(req.URL.Hostname())
  if dest!=origin && dest!="www."+origin && origin!="www."+dest {
   return fmt.Errorf("redirect to other host: %s",dest)
  }
  return nil
 }}
 result:=WebsiteCheck{Host:name,CDN:CDNInfo{Confidence:"unknown"}}
 var wg sync.WaitGroup
 var cname string
 wg.Add(1)
 go func(){
  defer wg.Done()
  cctx,ccancel:=context.WithTimeout(context.Background(),timeout)
  defer ccancel()
  host,err:=net.DefaultResolver.LookupCNAME(cctx,name)
  if err==nil{
   host=strings.TrimSuffix(host,".")
   if !strings.EqualFold(host,name){cname=host}
  }
 }()
 result=probeWebsite(ctx,client,name)
 wg.Wait()
 result.CNAME=cname
 // CNAME belongs to the requested hostname, but HTTP response headers may
 // belong to the final redirected hostname. Keep these as distinct evidence
 // rather than reporting a false CDN conflict across separate hosts.
 dnsEvidence:=detectCDN(cname,nil)
 redirectedHost:=""
 if result.FinalURL!=""{
  if u,err:=url.Parse(result.FinalURL);err==nil{redirectedHost=u.Hostname()}
 }
 if redirectedHost!=""&&!strings.EqualFold(redirectedHost,name){
  if dnsEvidence.Provider!=""{result.DNSCDN=&dnsEvidence}
  result.CDN=detectCDN("",result.responseHeaders)
 }else{
  result.CDN=detectCDN(cname,result.responseHeaders)
 }
 return result
}

func inspectWebsites(domain string,timeout time.Duration)[]WebsiteCheck{
 targets:=domainTargets(domain)
 reports:=make([]WebsiteCheck,len(targets))
 var wg sync.WaitGroup
 for index,host:=range targets{
  wg.Add(1)
  go func(i int,name string){defer wg.Done();reports[i]=checkWebsiteHost(name,timeout)}(index,host)
 }
 wg.Wait()
 return reports
}

func websiteStatus(website WebsiteCheck,lang string)string{
 if !website.Reachable {
  if lang=="en"{return "Unavailable"}
  return "不可访问"
 }
 if website.Healthy{
  if lang=="en"{return "OK"}
  return "正常"
 }
 if website.StatusCode==401||website.StatusCode==403{
  if lang=="en"{return "Access restricted"}
  return "访问受限"
 }
 if lang=="en"{return "HTTP error"}
 return "HTTP 异常"
}
func cdnText(cdn CDNInfo,lang string)string{
 if cdn.Provider==""{
  if cdn.Confidence=="conflict"{
   if lang=="en"{return "Conflicting evidence"}
   return "证据冲突"
  }
  if lang=="en"{return "Unknown"}
  return "未知"
 }
 if cdn.Confidence=="headers" {
  if lang=="en"{return cdn.Provider+" (header hint)"}
  return cdn.Provider+"（响应头线索）"
 }
 return cdn.Provider+" (CNAME)"
}
func formatWebsiteReport(results []WebsiteCheck,lang string)string{
 var out strings.Builder
 for _,w:=range results{
  status:=websiteStatus(w,lang)
  fmt.Fprintf(&out,"  %s | %s",w.Host,status)
  if w.StatusCode!=0{fmt.Fprintf(&out," (HTTP %d)",w.StatusCode)}
  if w.Reachable{fmt.Fprintf(&out," | %dms",w.LatencyMS)}
  fmt.Fprintf(&out," | CDN: %s\n",cdnText(w.CDN,lang))
  if w.DNSCDN!=nil {fmt.Fprintf(&out,"    DNS CNAME CDN (%s): %s\n",w.Host,cdnText(*w.DNSCDN,lang))}
  if w.FinalURL!=""&&w.FinalURL!="https://"+w.Host+"/"{fmt.Fprintf(&out,"    URL: %s\n",w.FinalURL)}
  if w.Error!="" {fmt.Fprintf(&out,"    %s: %s\n",map[bool]string{true:"原因",false:"Error"}[lang=="zh"],w.Error)}
 }
 return out.String()
}
