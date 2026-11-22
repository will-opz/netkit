package main

import (
 "bytes"
 "encoding/json"
 "fmt"
 "strings"
 "testing"
)

func sampleRenderingBundle()EvidenceBundle{
 return EvidenceBundle{
  SchemaVersion:"1",
  Plan:DiagnosticPlan{Target:"www.baidu.com",Host:"www.baidu.com",Port:443,Scheme:"https"},
  Status:"ok",Observer:"local_machine",
  Stages:[]DiagnosticStage{
   {ID:"dns.1",Layer:"dns",Status:"ok",DurationMS:37},
   {ID:"tcp.1",Layer:"tcp",Status:"ok",DurationMS:8},
   {ID:"tls.1",Layer:"tls",Status:"ok",DurationMS:100},
   {ID:"http.1",Layer:"http",Status:"ok",DurationMS:184},
  },
  Backends:&PinnedBackendReport{
   Status:"reachable",Checked:2,TotalResolved:2,OKCount:2,
   Results:[]PinnedBackendProbe{
    {ID:"backend.1",IP:"164.52.120.52",Status:"ok",HTTPStatusCode:200,HTTPProtocol:"HTTP/1.1",TLSALPN:"http/1.1",DurationMS:186,ConnectionMode:"direct_pinned_no_proxy"},
    {ID:"backend.2",IP:"98.98.225.192",Status:"ok",HTTPStatusCode:200,HTTPProtocol:"HTTP/1.1",TLSALPN:"http/1.1",DurationMS:246,ConnectionMode:"direct_pinned_no_proxy"},
   },
  },
  AIAnalysis:&AIAnalysis{
   Model:"test-model",
   Summary:"本次探测未观察到故障，两个地址均已验证；仍需区分单次观测与长期可用性。",
   EvidenceIDs:[]string{"dns.1","tcp.1","tls.1","http.1","backend.1","backend.2"},
   NextChecks:[]string{"如果问题再次发生，请在同一台机器上重复测量，并比较各个节点的耗时变化。"},
  },
 }
}
func TestDiagnoseTextWidthSnapshots(t *testing.T){
 for _,width:=range []int{60,80,120}{
  for _,verbose:=range []bool{false,true}{
   t.Run(fmt.Sprintf("%d_verbose_%v",width,verbose),func(t *testing.T){
    var buffer bytes.Buffer
    renderDiagnoseText(&buffer,sampleRenderingBundle(),diagnoseTextOptions{Width:width,Lang:"zh",Verbose:verbose,Color:false})
    out:=buffer.String()
    for _,line:=range strings.Split(strings.TrimSuffix(out,"\n"),"\n"){
     if actual:=displayWidth(line);actual>width{
      t.Fatalf("line exceeds %d columns (%d): %q",width,actual,line)
     }
    }
    for _,must:=range []string{"www.baidu.com","164.52.120.52","98.98.225.192","test-model"}{
     if !strings.Contains(out,must){t.Fatalf("missing %q: %s",must,out)}
    }
    if verbose{
     for _,must:=range []string{"dns.1","backend.1","ALPN","建议后续检查"}{
      if !strings.Contains(out,must){t.Fatalf("verbose missing %q: %s",must,out)}
     }
    }else{
     for _,absent:=range []string{"backend.1","ALPN","建议后续检查"}{
      if strings.Contains(out,absent){t.Fatalf("compact leaked detail %q: %s",absent,out)}
     }
    }
   })
  }
 }
}
func TestDiagnoseTextFailureAndAISuggestion(t *testing.T){
 b:=sampleRenderingBundle()
 b.Status="failed"
 b.FirstFailure="tls.1"
 b.Stages[2].Status="failed"
 b.Stages[2].Error="hostname_mismatch"
 b.Backends.Status="partial_failure"
 b.Backends.FailureCount=1
 b.Backends.Results[1].Status="tls_error"
 var out bytes.Buffer
 renderDiagnoseText(&out,b,diagnoseTextOptions{Width:60,Lang:"en"})
 if !strings.Contains(out.String(),"tls.1")||!strings.Contains(out.String(),"Suggestion:"){
  t.Fatalf("failed compact output suppressed necessary diagnostics: %s",out.String())
 }
}
func TestDiagnoseTextColorOptInNoANSI(t *testing.T){
 bundle:=sampleRenderingBundle()
 var plain bytes.Buffer
 renderDiagnoseText(&plain,bundle,diagnoseTextOptions{Width:80,Color:false})
 if strings.Contains(plain.String(),"\x1b["){t.Fatal("plain text has ANSI escapes")}
 var colored bytes.Buffer
 renderDiagnoseText(&colored,bundle,diagnoseTextOptions{Width:80,Color:true})
 if !strings.Contains(colored.String(),"\x1b["){t.Fatal("color mode missing ANSI escapes")}
}
func TestDiagnoseJSONIndependentOfRendering(t *testing.T){
 bundle:=sampleRenderingBundle()
 before,err:=json.Marshal(bundle)
 if err!=nil{t.Fatal(err)}
 var out bytes.Buffer
 renderDiagnoseText(&out,bundle,diagnoseTextOptions{Width:60,Verbose:true,Color:true})
 after,err:=json.Marshal(bundle)
 if err!=nil{t.Fatal(err)}
 if !bytes.Equal(before,after){t.Fatalf("rendering changed JSON:\n%s\n%s",before,after)}
}
func TestTerminalDisplayWidthMultilingual(t *testing.T){
 if displayWidth("中文ABC")!=7{t.Fatalf("CJK width wrong: %d",displayWidth("中文ABC"))}
 output:=wrapText("本机对 www.baidu.com 的此次综合网络诊断正常，HTTP 返回 200。",60,"  ")
 for _,line:=range strings.Split(output,"\n"){
  if displayWidth(line)>60{t.Fatalf("CJK wrapping exceeds width: %q",line)}
 }
}

func TestCompactVerdictIsDeterministicAndDetailedModePreservesAI(t *testing.T){
 b:=sampleRenderingBundle()
 b.AIAnalysis.Summary="VERBATIM_MODEL_TEXT_SHOULD_ONLY_APPEAR_IN_VERBOSE"
 var compact bytes.Buffer
 renderDiagnoseText(&compact,b,diagnoseTextOptions{Width:60,Lang:"zh"})
 if strings.Contains(compact.String(),"VERBATIM_MODEL_TEXT")||!strings.Contains(compact.String(),"2 个 IP 首跳均返回 HTTP 2xx"){
  t.Fatalf("compact verdict leaks long model output: %s",compact.String())
 }
 if strings.Contains(compact.String(),"reachable")||strings.Contains(compact.String(),"2xx=2"){
  t.Fatalf("compact status not localized: %s",compact.String())
 }
 var verbose bytes.Buffer
 renderDiagnoseText(&verbose,b,diagnoseTextOptions{Width:80,Lang:"zh",Verbose:true})
 if !strings.Contains(verbose.String(),"VERBATIM_MODEL_TEXT")||!strings.Contains(verbose.String(),"2xx=2"){
  t.Fatalf("verbose missing original analysis or counters: %s",verbose.String())
 }
}
func TestCompactVerdictDoesNotConflateRedirectWithSuccess(t *testing.T){
 b:=sampleRenderingBundle()
 b.Backends.Status="redirect_only"
 b.Backends.OKCount=0
 b.Backends.RedirectCount=2
 for i:=range b.Backends.Results{
  b.Backends.Results[i].Status="redirect"
  b.Backends.Results[i].HTTPStatusCode=301
 }
 var out bytes.Buffer
 renderDiagnoseText(&out,b,diagnoseTextOptions{Width:60,Lang:"zh"})
 if !strings.Contains(out.String(),"仅重定向")||!strings.Contains(out.String(),"尚未验证后续跳转链"){
  t.Fatalf("misleading compact redirect summary: %s",out.String())
 }
}
func TestFriendlyStatusEnglishUnchanged(t *testing.T){
 if friendlyBackendStatus("reachable","en")!="reachable"||friendlyDiagnosisStatus("ok","en")!="ok"{t.Fatal("English status compatibility broken")}
}

func TestTemporalCompactAndVerboseWidth(t *testing.T){
 b:=sampleRenderingBundle()
 b.Backends=nil
 b.Temporal=&TemporalSampling{Requested:3,Completed:3,Status:"intermittent_or_failed",HealthyRounds:2,FailedRounds:1,
  Rounds:[]TemporalRound{
   {ID:"round.1",Status:"ok",DNSStatus:"ok",TCPStatus:"ok",TLSStatus:"ok",HTTPStatus:"ok",FinalHTTPCode:200,ResolvedIPs:[]string{"192.0.2.1"},ObservedAt:"2026-11-22T00:00:00Z"},
   {ID:"round.2",Status:"failed",FirstFailure:"tcp.1",DNSStatus:"ok",TCPStatus:"failed",TLSStatus:"skipped",HTTPStatus:"skipped",ResolvedIPs:[]string{"192.0.2.1"},ObservedAt:"2026-11-22T00:00:05Z"},
   {ID:"round.3",Status:"ok",DNSStatus:"ok",TCPStatus:"ok",TLSStatus:"ok",HTTPStatus:"ok",FinalHTTPCode:200,ResolvedIPs:[]string{"192.0.2.1"},ObservedAt:"2026-11-22T00:00:10Z"},
  }}
 for _,width:=range []int{60,80,120}{
  for _,verbose:=range []bool{false,true}{
   var out bytes.Buffer
   renderDiagnoseText(&out,b,diagnoseTextOptions{Width:width,Verbose:verbose,Lang:"zh"})
   if !strings.Contains(out.String(),"round.2")||!strings.Contains(out.String(),"1 轮失败"){
    t.Fatalf("temporal failure hidden: %s",out.String())
   }
   for _,line:=range strings.Split(strings.TrimSpace(out.String()),"\n"){
    if n:=displayWidth(line);n>width{t.Fatalf("%d-column output overflow (%d): %q",width,n,line)}
   }
  }
 }
}
func TestRepeatedPinnedSamplesCompactAndDetailed(t *testing.T){
 b:=sampleRenderingBundle()
 st:=buildSampleStats(b.Backends.Results[0],3)
 for _,ms:=range []int64{12,18,25}{
  recordBackendSample(&st,PinnedBackendProbe{Status:"ok",HTTPStatusCode:200,DurationMS:ms})
 }
 finalizeSampleStats(&st)
 b.Sampling=&BackendSampling{Requested:3,TotalPlanned:3,TotalCompleted:3,Nodes:[]BackendSampleStatistics{st}}
 for _,verbose:=range []bool{false,true}{
  var out bytes.Buffer
  renderDiagnoseText(&out,b,diagnoseTextOptions{Width:60,Verbose:verbose,Lang:"zh"})
  if !strings.Contains(out.String(),"median=18ms")||!strings.Contains(out.String(),"p95=25ms"){
   t.Fatalf("sampling statistics missing: %s",out.String())
  }
  if !verbose&&strings.Contains(out.String(),"#2 "){t.Fatalf("compact includes raw samples: %s",out.String())}
  if verbose&&!strings.Contains(out.String(),"#2 "){t.Fatalf("verbose raw samples missing: %s",out.String())}
  for _,line:=range strings.Split(strings.TrimSpace(out.String()),"\n"){
   if n:=displayWidth(line);n>60{t.Fatalf("output too wide (%d): %q",n,line)}
  }
 }
}
