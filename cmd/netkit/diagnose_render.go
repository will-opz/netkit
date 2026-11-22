package main

import (
 "fmt"
 "io"
 "os"
 "strconv"
 "strings"
 "unicode"
)

type diagnoseTextOptions struct {
 Lang string
 Verbose bool
 Width int
 Color bool
}

// Terminal presentation is deliberately independent of network evidence.
// JSON serialization continues to marshal EvidenceBundle unchanged.
func terminalTextOptions(lang string,verbose bool)diagnoseTextOptions{
 width:=100
 if raw:=os.Getenv("COLUMNS");raw!=""{
  if n,err:=strconv.Atoi(raw);err==nil&&n>=40&&n<=300{width=n}
 }
 info,err:=os.Stdout.Stat()
 interactive:=err==nil&&(info.Mode()&os.ModeCharDevice)!=0
 _,noColor:=os.LookupEnv("NO_COLOR")
 color:=interactive&&!noColor&&os.Getenv("TERM")!="dumb"
 return diagnoseTextOptions{Lang:lang,Verbose:verbose,Width:width,Color:color}
}
func screenWidth(r rune)int{
 if unicode.Is(unicode.Mn,r)||unicode.Is(unicode.Me,r){return 0}
 if r>=0x1100&&(r<=0x115f||r>=0x2329&&r<=0x232a||
  r>=0x2e80&&r<=0xa4cf||r>=0xac00&&r<=0xd7a3||
  r>=0xf900&&r<=0xfaff||r>=0xfe10&&r<=0xfe6f||
  r>=0xff00&&r<=0xff60||r>=0xffe0&&r<=0xffe6||
  r>=0x1f300&&r<=0x1faff||r>=0x20000&&r<=0x3fffd){return 2}
 return 1
}
func displayWidth(s string)int{
 n:=0
 for _,r:=range s{n+=screenWidth(r)}
 return n
}
func takeWidth(s string,n int)(string,string){
 count:=0
 for i,r:=range s{
  w:=screenWidth(r)
  if count+w>n{return s[:i],s[i:]}
  count+=w
 }
 return s,""
}
func wrapText(text string,width int,indent string)string{
 avail:=width-displayWidth(indent)
 if avail<8{avail=8}
 var out strings.Builder
 for i,line:=range strings.Split(text,"\n"){
  if i>0{out.WriteByte('\n')}
  line=strings.TrimSpace(line)
  first:=true
  for line!=""{
   if !first{out.WriteByte('\n')}
   first=false
   chunk,left:=takeWidth(line,avail)
   if left!=""{
    if j:=strings.LastIndexAny(chunk," \t");j>0&&displayWidth(chunk[j+1:])<avail/3{
     left=strings.TrimSpace(chunk[j+1:])+left
     chunk=strings.TrimSpace(chunk[:j])
    }
   }
   out.WriteString(indent)
   out.WriteString(chunk)
   line=strings.TrimLeft(left," \t")
  }
  if first{out.WriteString(indent)}
 }
 return out.String()
}
func coloredStatus(s string,enabled bool)string{
 if !enabled{return s}
 color:="\x1b[36m"
 switch s{
 case "ok","connected","reachable":color="\x1b[32m"
 case "degraded","restricted","redirect","redirect_only","restricted_only","mixed_responses","incomplete":color="\x1b[33m"
 case "failed","tcp_error","tls_error","http_error","partial_failure","timeout":color="\x1b[31m"
 case "skipped":color="\x1b[90m"
 }
 return color+s+"\x1b[0m"
}
func statusSymbol(s string)string{
 switch s{
 case "ok","connected","reachable":return "✓"
 case "failed","tcp_error","tls_error","http_error","partial_failure","timeout":return "✗"
 case "skipped":return "-"
 default:return "!"
 }
}
func renderDiagnoseText(w io.Writer,b EvidenceBundle,opt diagnoseTextOptions){
 width:=opt.Width
 if width<40{width=80}
 label:=func(zh,en string)string{return chooseAIText(opt.Lang,zh,en)}
 state:=label("正常","ok")
 if b.Status!="ok"{state=b.Status}
 fmt.Fprintln(w,wrapText(label("NetKit · 综合诊断","NetKit · Diagnostic")+" · "+b.Plan.Target,width,""))
 fmt.Fprintf(w,"%s %s\n",statusSymbol(b.Status),coloredStatus(state,opt.Color))
 if opt.Verbose{
  for _,s:=range b.Stages{
   line:=fmt.Sprintf("  %s %-5s %-12s %dms [%s]",statusSymbol(s.Status),strings.ToUpper(s.Layer),s.Status,s.DurationMS,s.ID)
   fmt.Fprintln(w,wrapText(line,width,""))
   if s.Error!=""{fmt.Fprintln(w,wrapText(label("    原因: ","    Reason: ")+s.Error,width,"    "))}
  }
 }else{
  var parts []string
  for _,s:=range b.Stages{
   parts=append(parts,fmt.Sprintf("%s %s %dms",statusSymbol(s.Status),strings.ToUpper(s.Layer),s.DurationMS))
  }
  fmt.Fprintln(w,wrapText(strings.Join(parts,"  ·  "),width,"  "))
  if b.FirstFailure!=""{fmt.Fprintln(w,wrapText(label("  首个异常: ","  First failure: ")+b.FirstFailure,width,"  "))}
 }
 if b.Backends!=nil{
  r:=b.Backends
  fmt.Fprintln(w)
  fmt.Fprintln(w,wrapText(fmt.Sprintf("%s: %s · %d/%d · 2xx=%d 3xx=%d restricted=%d errors=%d",
   label("逐 IP","Pinned IPs"),coloredStatus(r.Status,opt.Color),r.Checked,r.TotalResolved,
   r.OKCount,r.RedirectCount,r.RestrictedCount,r.FailureCount),width,""))
  for _,p:=range r.Results{
   code:=""
   if p.HTTPStatusCode>0{code=fmt.Sprintf("HTTP %d",p.HTTPStatusCode)}
   protocol:=p.HTTPProtocol
   if protocol==""{protocol=p.Status}
   line:=fmt.Sprintf("  %s %s  %s  %dms  %s",statusSymbol(p.Status),p.IP,code,p.DurationMS,protocol)
   fmt.Fprintln(w,wrapText(line,width,"    "))
   if opt.Verbose{
    detail:=fmt.Sprintf("    %s · %s",p.ID,p.ConnectionMode)
    if p.TLSALPN!=""{detail+=" · ALPN "+p.TLSALPN}
    if p.TLSVersion!=""{detail+=" · "+p.TLSVersion}
    if p.RedirectHost!=""{detail+=" · redirect "+p.RedirectHost}
    if p.ErrorCode!=""{detail+=" · "+p.ErrorCode}
    fmt.Fprintln(w,wrapText(detail,width,"    "))
   }else if p.Status!="ok"{
    detail:=p.RedirectHost
    if detail==""{detail=p.ErrorCode}
    if detail!=""{fmt.Fprintln(w,wrapText("    "+detail,width,"    "))}
   }
  }
  if r.Truncated||r.Checked<r.TotalResolved{fmt.Fprintln(w,wrapText(label("  注意：未覆盖全部解析 IP","  Note: not all resolved IPs checked"),width,"  "))}
  if opt.Verbose{fmt.Fprintln(w,wrapText("  "+r.Assessment,width,"  "))}
 }
 if b.AIAnalysis!=nil{
  a:=b.AIAnalysis
  fmt.Fprintln(w)
  fmt.Fprintln(w,wrapText("AI · "+a.Model,width,""))
  fmt.Fprintln(w,wrapText(a.Summary,width,"  "))
  for _,h:=range a.Hypotheses{
   text:=label("可能原因: ","Possible cause: ")+h.Cause
   if opt.Verbose{text+=fmt.Sprintf(" (%s · %s)",h.Confidence,strings.Join(h.EvidenceIDs,", "))}
   fmt.Fprintln(w,wrapText(text,width,"  "))
  }
  if opt.Verbose{
   fmt.Fprintln(w,wrapText(label("  证据: ","  Evidence: ")+strings.Join(a.EvidenceIDs,", "),width,"  "))
   if len(a.NextChecks)>0{fmt.Fprintln(w,label("建议后续检查:","Suggested next checks:"))}
   for _,check:=range a.NextChecks{fmt.Fprintln(w,wrapText("- "+check,width,"  "))}
  }else if b.Status!="ok"||b.Backends!=nil&&b.Backends.FailureCount>0{
   if len(a.NextChecks)>0{fmt.Fprintln(w,wrapText(label("建议: ","Suggestion: ")+a.NextChecks[0],width,"  "))}
  }
 }else if b.AIError!=""{
  fmt.Fprintln(w,wrapText("AI unavailable: "+b.AIError,width,"  "))
 }
 if opt.Verbose{
  fmt.Fprintln(w)
  fmt.Fprintln(w,label("详细机器证据: --output json","Machine-readable evidence: --output json"))
 }
}
