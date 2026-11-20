package main

import (
 "context"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "net"
 "io"
 "net/http"
 "net/url"
 "strings"
 "time"
)

type HTTPHop struct {
 URL string `json:"url"`
 StatusCode int `json:"status_code"`
 Location string `json:"location,omitempty"`
 DurationMS int64 `json:"duration_ms"`
 Phases HTTPPhases `json:"phases"`
}
type HTTPReport struct {
 Target string `json:"target"`
 FinalURL string `json:"final_url,omitempty"`
 Hops []HTTPHop `json:"hops"`
 Status string `json:"status"`
 Redirects int `json:"redirects"`
 HTTPSDowngrade bool `json:"https_downgrade,omitempty"`
 Error string `json:"error,omitempty"`
}

func normalizeHTTPURL(input string)(string,error){
 input=strings.TrimSpace(input)
 if input==""{return "",errors.New("empty HTTP target")}
 if !strings.Contains(input,"://"){input="https://"+input}
 u,err:=url.Parse(input)
 if err!=nil{return "",err}
 if (u.Scheme!="http"&&u.Scheme!="https")||u.Hostname()==""||u.User!=nil||u.Opaque!=""||u.Fragment!="" {
  return "",errors.New("target must be an HTTP(S) URL without credentials or fragments")
 }
 if strings.ContainsAny(u.Host," \t\n\r"){return "",errors.New("invalid host")}
 if u.Port()!="" {
  for _,c:=range u.Port(){if c<'0'||c>'9'{return "",errors.New("invalid port")}}
 }
 return u.String(),nil
}
func httpState(code int)string{
 switch {
 case code>=200&&code<300:return "ok"
 case code==401||code==403||code==407||code==429:return "restricted"
 case code>=300&&code<400:return "redirect_incomplete"
 case code>=400&&code<600:return "http_error"
 default:return "unknown"
 }
}

// traceHTTP observes each HTTP redirect response. A local diagnostic permits
// local/private endpoints intentionally and never downloads the response body.
func traceHTTP(ctx context.Context,client *http.Client,target string,limit int)HTTPReport{
 r:=HTTPReport{Target:target,Hops:[]HTTPHop{},Status:"unknown"}
 current:=target
 seen:=map[string]bool{}
 probe:=*client
 probe.CheckRedirect=func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}
 for {
  if seen[current]{r.Status="redirect_loop";r.Error="redirect loop detected";r.FinalURL=current;return r}
  seen[current]=true
  recorder:=&httpPhaseRecorder{}
  req,err:=http.NewRequestWithContext(withHTTPPhaseTrace(ctx,recorder),http.MethodGet,current,nil)
  if err!=nil{r.Status="request_error";r.Error=err.Error();r.FinalURL=current;return r}
  req.Header.Set("User-Agent",agent)
  started:=time.Now()
  res,err:=probe.Do(req)
  elapsed:=time.Since(started).Milliseconds()
  if err!=nil{
   r.Status="network_error"
   var ne net.Error
   if errors.Is(err,context.DeadlineExceeded)||(errors.As(err,&ne)&&ne.Timeout()){r.Status="timeout"}
   r.Error=err.Error();r.FinalURL=current;return r
  }
  // Drain no body: reading arbitrary HTML is unnecessary for redirect diagnosis.
  io.Copy(io.Discard,io.LimitReader(res.Body,0))
  res.Body.Close()
  hop:=HTTPHop{URL:current,StatusCode:res.StatusCode,DurationMS:elapsed,Phases:recorder.result()}
  location:=res.Header.Get("Location")
  if res.StatusCode==301||res.StatusCode==302||res.StatusCode==303||res.StatusCode==307||res.StatusCode==308{
   hop.Location=location
  }
  r.Hops=append(r.Hops,hop)
  r.FinalURL=current
  r.Status=httpState(res.StatusCode)
  if hop.Location==""||r.Status!="redirect_incomplete" {return r}
  if r.Redirects>=limit {r.Status="redirect_limit";r.Error="maximum redirects exceeded";return r}
  parsed,err:=url.Parse(hop.Location)
  if err!=nil{r.Status="invalid_redirect";r.Error=err.Error();return r}
  next:=req.URL.ResolveReference(parsed)
  if (next.Scheme!="http"&&next.Scheme!="https")||next.Hostname()==""||next.User!=nil||next.Opaque!="" {
   r.Status="invalid_redirect";r.Error="redirect to unsupported URL";return r
  }
  next.Fragment=""
  if req.URL.Scheme=="https"&&next.Scheme=="http"{r.HTTPSDowngrade=true}
  current=next.String()
  r.Redirects++
 }
}

func httpHelp(){
 fmt.Println("用法: netkit http [-timeout 5s] [-max-redirects 5] [--output text|json] [-lang zh|en] DOMAIN|URL")
 fmt.Println("示例: netkit http baidu.com")
 fmt.Println("      netkit http --output json https://example.com/")
 fmt.Println("只检查给定主机/URL，逐跳显示跳转；不自动检查 www 子域名")
}
func runHTTP(args []string)error{
 if len(args)==0||args[0]=="-h"||args[0]=="--help"{httpHelp();return nil}
 fs:=flag.NewFlagSet("http",flag.ContinueOnError)
 timeout:=fs.Duration("timeout",5*time.Second,"per-hop timeout")
 maxRedirects:=fs.Int("max-redirects",5,"maximum redirects (0-20)")
 output:=fs.String("output","text","text or json")
 lang:=fs.String("lang","zh","zh or en")
 if err:=fs.Parse(args);err!=nil{return err}
 if *timeout<=0{return errors.New("-timeout must be positive")}
 if *maxRedirects<0||*maxRedirects>20{return errors.New("-max-redirects must be 0-20")}
 if *lang!="zh"&&*lang!="en"{return errors.New("-lang must be zh or en")}
 format,err:=resolveOutputFormat(*output,false)
 if err!=nil{return err}
 if fs.NArg()!=1{return errors.New("expected one domain or URL")}
 target,err:=normalizeHTTPURL(fs.Arg(0))
 if err!=nil{return err}
 ctx,cancel:=context.WithTimeout(context.Background(),time.Duration(*maxRedirects+1)*(*timeout))
 defer cancel()
 client:=&http.Client{Timeout:*timeout}
 report:=traceHTTP(ctx,client,target,*maxRedirects)
 if format=="json"{
  b,err:=json.MarshalIndent(report,"","  ");if err!=nil{return err};fmt.Println(string(b))
 }else{
  label:=func(zh,en string)string{if *lang=="en"{return en};return zh}
  fmt.Printf("%s: %s\n",label("HTTP 目标","HTTP target"),report.Target)
  for i,hop:=range report.Hops{
   fmt.Printf("  %d. HTTP %d | %dms | %s\n",i+1,hop.StatusCode,hop.DurationMS,hop.URL)
   fmt.Print(formatHTTPPhases(hop.Phases,*lang))
   if hop.Location!=""{fmt.Printf("     Location: %s\n",hop.Location)}
  }
  fmt.Printf("%s: %s | %s: %d\n",label("结果","Result"),report.Status,label("跳转次数","Redirects"),report.Redirects)
  if report.HTTPSDowngrade{fmt.Println(label("警告: HTTPS 降级到 HTTP","Warning: HTTPS to HTTP downgrade"))}
  if report.Error!=""{fmt.Printf("%s: %s\n",label("错误","Error"),report.Error)}
 }
 if report.Status!="ok"{return fmt.Errorf("HTTP diagnostic: %s",report.Status)}
 return nil
}
