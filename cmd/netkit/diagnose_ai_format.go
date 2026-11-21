package main

import (
 "fmt"
 "strings"
)

// formatAIAnalysis renders the optional model output without changing the
// deterministic diagnosis or hiding its evidence references.
func formatAIAnalysis(a AIAnalysis,lang string)string{
 var out strings.Builder
 fmt.Fprintf(&out,"AI [%s]: %s\n",a.Model,a.Summary)
 fmt.Fprintf(&out,"  [%s: %s]\n",chooseAIText(lang,"证据","Evidence"),strings.Join(a.EvidenceIDs,", "))
 if len(a.Hypotheses)>0{
  fmt.Fprintf(&out,"%s:\n",chooseAIText(lang,"可能原因（模型推断，非已证实事实）","Possible causes (model hypotheses)"))
  for _,h:=range a.Hypotheses{
   fmt.Fprintf(&out,"  - %s (%s: %s; %s: %s)\n",h.Cause,
    chooseAIText(lang,"置信度","confidence"),h.Confidence,
    chooseAIText(lang,"证据","evidence"),strings.Join(h.EvidenceIDs,", "))
  }
 }
 if len(a.NextChecks)>0{
  fmt.Fprintf(&out,"%s:\n",chooseAIText(lang,"建议后续检查","Suggested next checks"))
  for _,next:=range a.NextChecks{fmt.Fprintf(&out,"  - %s\n",next)}
 }
 return out.String()
}
func chooseAIText(lang,zh,en string)string{
 if lang=="en"{return en}
 return zh
}
