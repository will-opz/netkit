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
 case "ok","connected","reachable","正常","全部首跳正常":color="\x1b[32m"
 case "degraded","restricted","redirect","redirect_only","restricted_only","mixed_responses","incomplete","仅重定向","访问受限","混合响应","检查不完整":color="\x1b[33m"
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
// Human-readable labels never replace the stable English JSON status codes.
func friendlyDiagnosisStatus(status,lang string)string{
 switch status{
 case "ok":return chooseAIText(lang,"正常","ok")
 case "degraded":return chooseAIText(lang,"部分受限","degraded")
 case "failed":return chooseAIText(lang,"失败","failed")
 default:return status
 }
}
func friendlyBackendStatus(status,lang string)string{
 if lang=="en"{return status}
 switch status{
 case "reachable":return "全部首跳正常"
 case "redirect_only":return "仅重定向"
 case "restricted_only":return "访问受限"
 case "mixed_responses":return "混合响应"
 case "partial_failure":return "部分失败"
 case "failed":return "失败"
 case "incomplete":return "检查不完整"
 case "not_checked":return "未检查"
 default:return status
 }
}
// The compact verdict is built only from deterministic evidence, never by
// heuristically shortening the model's free-form prose.
func compactDiagnosticVerdict(b EvidenceBundle,lang string)string{
 if b.Temporal!=nil{
  t:=b.Temporal
  label:=func(zh,en string)string{return chooseAIText(lang,zh,en)}
  if t.Incomplete{return label("跨时间检查未完成，请根据已采集轮次判断。","Temporal checks were incomplete; use the observed rounds only.")}
  if t.FailedRounds>0||t.DegradedRounds>0{
   return fmt.Sprintf(label("跨时间检查发现 %d 轮失败、%d 轮受限；需查看发生时的证据。","Temporal checks saw %d failed and %d restricted rounds; inspect those observations."),t.FailedRounds,t.DegradedRounds)
  }
  if t.DNSChanges>0{
   return fmt.Sprintf(label("本次全部 %d 轮正常，DNS 地址集合变化 %d 次；变化本身并非故障。","All %d temporal rounds passed; DNS address set changed %d times, which is not by itself a fault."),t.Completed,t.DNSChanges)
  }
  return fmt.Sprintf(label("本机连续 %d 轮检测均正常；不能据此保证长期可用性。","All %d local diagnostic rounds passed; long-term availability remains unproven."),t.Completed)
 }

 label:=func(zh,en string)string{return chooseAIText(lang,zh,en)}
 if b.Status!="ok"{
  if b.FirstFailure!=""{return label("本次检测发现异常，首个失败阶段：","A failure was observed at ")+b.FirstFailure}
  return label("本次检测存在异常或访问限制。","This diagnosis contains a failure or restriction.")
 }
 if b.Backends==nil{return label("本机此次综合探测未发现故障。","No failure was observed in this local diagnosis.")}
 r:=b.Backends
 if r.Status=="reachable"&&r.OKCount==r.Checked&&r.Checked==r.TotalResolved{
  return fmt.Sprintf(label("本次未发现故障；%d 个 IP 首跳均返回 HTTP 2xx。","No fault observed; %d IPs returned first-hop HTTP 2xx."),r.Checked)
 }
 if r.RedirectCount==r.Checked&&r.Checked>0{return label("各 IP 首跳均返回重定向，尚未验证后续跳转链。","All checked IPs redirect; destination chains remain unverified.")}
 if r.RestrictedCount==r.Checked&&r.Checked>0{return label("各 IP 首跳均受到访问限制。","All checked IPs returned restricted responses.")}
 if r.FailureCount>0{return label("部分逐 IP 探测失败，请查看节点详情。","Some per-IP probes failed; inspect node details.")}
 return label("常规探测正常；逐 IP 结果仍有差异或未覆盖全部地址。","Main probe passed; per-IP outcomes differ or coverage is incomplete.")
}
func renderDiagnoseText(w io.Writer,b EvidenceBundle,opt diagnoseTextOptions){
 width:=opt.Width
 if width<40{width=80}
 label:=func(zh,en string)string{return chooseAIText(opt.Lang,zh,en)}
 state:=friendlyDiagnosisStatus(b.Status,opt.Lang)
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
  summary:=fmt.Sprintf("%s: %s · %d/%d",label("逐 IP","Pinned IPs"),friendlyBackendStatus(r.Status,opt.Lang),r.Checked,r.TotalResolved)
  if opt.Verbose{summary+=fmt.Sprintf(" · 2xx=%d 3xx=%d restricted=%d errors=%d",r.OKCount,r.RedirectCount,r.RestrictedCount,r.FailureCount)}
  fmt.Fprintln(w,wrapText(summary,width,""))
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
 if b.Temporal!=nil{
  t:=b.Temporal
  fmt.Fprintln(w)
  title:=fmt.Sprintf("%s: %d/%d · %s · DNS Δ=%d",
   label("跨时间诊断","Temporal diagnostics"),t.Completed,t.Requested,t.Status,t.DNSChanges)
  fmt.Fprintln(w,wrapText(title,width,""))
  for _,round:=range t.Rounds{
   line:=fmt.Sprintf("  %s %s · DNS IP=%d · HTTP=%d",round.ID,round.Status,len(round.ResolvedIPs),round.FinalHTTPCode)
   if opt.Verbose{
    line+=fmt.Sprintf(" · %s · %dms",round.ObservedAt,round.DurationMS)
    if round.FirstFailure!=""{line+=" · "+round.FirstFailure}
    line+=fmt.Sprintf(" · DNS=%s TCP=%s TLS=%s HTTP=%s",round.DNSStatus,round.TCPStatus,round.TLSStatus,round.HTTPStatus)
   }
   fmt.Fprintln(w,wrapText(line,width,"  "))
  }
  if t.Incomplete{fmt.Fprintln(w,wrapText(label("  注意：未完成全部预定轮次","  Note: not all rounds were completed"),width,"  "))}
 }
 if b.Sampling!=nil{
  stats:=b.Sampling
  fmt.Fprintln(w)
  fmt.Fprintln(w,wrapText(fmt.Sprintf("%s: %d/%d (%s %d)",
   label("重复采样","Repeat samples"),stats.TotalCompleted,stats.TotalPlanned,
   label("每 IP 计划","planned per IP"),stats.Requested),width,""))
  for _,node:=range stats.Nodes{
   pct:=label("无 HTTP 响应","no HTTP response")
   if node.MedianMS!=nil&&node.P95MS!=nil{
    pct=fmt.Sprintf("median=%dms p95=%dms",*node.MedianMS,*node.P95MS)
   }
   line:=fmt.Sprintf("  %s · %d/%d · 2xx=%d redirect=%d restricted=%d errors=%d · %s",
    node.IP,node.Completed,node.Planned,node.HTTP2xx,node.Redirects,node.Restricted,node.Errors,pct)
   if !opt.Verbose{
    line=fmt.Sprintf("  %s · %d/%d · %s",node.IP,node.Completed,node.Planned,pct)
    if node.Errors>0{line+=fmt.Sprintf(" · errors=%d",node.Errors)}
   }
   fmt.Fprintln(w,wrapText(line,width,"  "))
   if opt.Verbose{
    for _,sample:=range node.Samples{
     fmt.Fprintln(w,wrapText(fmt.Sprintf("    #%d %s %dms HTTP %d %s %s",
      sample.Index,sample.Status,sample.DurationMS,sample.HTTPStatusCode,sample.HTTPProtocol,sample.TLSALPN),width,"    "))
    }
   }
  }
  if stats.Incomplete{fmt.Fprintln(w,wrapText(label("  注意：部分计划样本未执行","  Note: some planned samples were not executed"),width,"  "))}
  if !opt.Verbose{fmt.Fprintln(w,wrapText(label("  注：小样本 P95 为描述值，不代表长期基线","  Note: small-sample P95 is descriptive, not a baseline"),width,"  "))}
 }
 if b.AIAnalysis!=nil{
  a:=b.AIAnalysis
  fmt.Fprintln(w)
  heading:="AI · "+a.Model
  if !opt.Verbose{heading=label("检测摘要 · AI 已分析: ","Diagnostic summary · AI analyzed: ")+a.Model}
  fmt.Fprintln(w,wrapText(heading,width,""))
  if opt.Verbose{
   fmt.Fprintln(w,wrapText(a.Summary,width,"  "))
  }else{
   fmt.Fprintln(w,wrapText(compactDiagnosticVerdict(b,opt.Lang),width,"  "))
  }
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
