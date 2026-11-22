package main

import (
 "context"
 "strconv"
 "sort"
 "strings"
 "time"
)

// TemporalSampling repeats the complete domain diagnostic with a fresh DNS
// resolution on every round. Unlike pinned per-IP repeat sampling, it tracks
// changes in the path selected by the resolver over time.
type TemporalSampling struct {
 Requested int `json:"requested"`
 Interval string `json:"interval"`
 Completed int `json:"completed"`
 Incomplete bool `json:"incomplete,omitempty"`
 Status string `json:"status"`
 HealthyRounds int `json:"healthy_rounds"`
 FailedRounds int `json:"failed_rounds"`
 DegradedRounds int `json:"degraded_rounds"`
 DNSChanges int `json:"dns_changes"`
 Rounds []TemporalRound `json:"rounds"`
}
type TemporalRound struct {
 ID string `json:"id"`
 ObservedAt string `json:"observed_at"`
 Status string `json:"status"`
 FirstFailure string `json:"first_failure,omitempty"`
 ResolvedIPs []string `json:"resolved_ips,omitempty"`
 DNSStatus string `json:"dns_status"`
 TCPStatus string `json:"tcp_status"`
 TLSStatus string `json:"tls_status,omitempty"`
 HTTPStatus string `json:"http_status"`
 FinalHTTPCode int `json:"final_http_code,omitempty"`
 DurationMS int64 `json:"duration_ms"`
}

type TemporalProbeFn func(context.Context,DiagnosticPlan,time.Duration)EvidenceBundle

func temporalRoundFromEvidence(r EvidenceBundle,index int)TemporalRound{
 out:=TemporalRound{
  ID:"round."+strconv.Itoa(index),ObservedAt:r.ObservedAt,Status:r.Status,
  FirstFailure:r.FirstFailure,DurationMS:r.DurationMS,
 }
 for _,stage:=range r.Stages{
  switch stage.Layer{
  case "dns":
   out.DNSStatus=stage.Status
   if stage.DNS!=nil{out.ResolvedIPs=append([]string(nil),stage.DNS.IPs...)}
  case "tcp":out.TCPStatus=stage.Status
  case "tls":out.TLSStatus=stage.Status
  case "http":
   out.HTTPStatus=stage.Status
   if stage.HTTP!=nil&&len(stage.HTTP.Hops)>0{
    out.FinalHTTPCode=stage.HTTP.Hops[len(stage.HTTP.Hops)-1].StatusCode
   }
  }
 }
 return out
}
func temporalIPSignature(ips []string)string{
 copyIPs:=append([]string(nil),ips...)
 sort.Strings(copyIPs)
 return strings.Join(copyIPs,",")
}
func sampleDomainOverTime(ctx context.Context,first EvidenceBundle,repeats int,interval,timeLimit time.Duration,probe TemporalProbeFn)TemporalSampling{
 out:=TemporalSampling{Requested:repeats,Interval:interval.String(),Rounds:[]TemporalRound{}}
 if repeats<1||repeats>maxPinnedRepeat{return out}
 out.Rounds=append(out.Rounds,temporalRoundFromEvidence(first,1))
 for i:=2;i<=repeats;i++{
  timer:=time.NewTimer(interval)
  select{
  case <-ctx.Done():
   if !timer.Stop(){select{case <-timer.C:default:}}
  case <-timer.C:
  }
  if ctx.Err()!=nil{break}
  roundCtx,cancel:=context.WithTimeout(ctx,10*timeLimit)
  report:=probe(roundCtx,first.Plan,timeLimit)
  cancel()
  out.Rounds=append(out.Rounds,temporalRoundFromEvidence(report,i))
 }
 out.Completed=len(out.Rounds)
 out.Incomplete=out.Completed<repeats
 previous:=""
 for i,round:=range out.Rounds{
  switch round.Status{
  case "ok":out.HealthyRounds++
  case "degraded":out.DegradedRounds++
  default:out.FailedRounds++
  }
  signature:=temporalIPSignature(round.ResolvedIPs)
  if i>0&&signature!=""&&previous!=""&&signature!=previous{out.DNSChanges++}
  previous=signature
 }
 switch{
 case out.Incomplete:out.Status="incomplete"
 case out.FailedRounds>0||out.DegradedRounds>0:out.Status="intermittent_or_failed"
 case out.DNSChanges>0:out.Status="dns_addresses_changed"
 default:out.Status="stable_observed"
 }
 return out
}
