package main

import (
 "bufio"
 _ "embed"
 "strings"
 "sync"
)

// Public Suffix List snapshot from https://publicsuffix.org/list/
// Embedded with MPL-2.0 notice retained in public_suffix_list.dat.
// The snapshot is immutable until an explicit source update and review.
//go:embed public_suffix_list.dat
var publicSuffixSource string

type suffixRules struct {
 exact map[string]bool
 wildcard map[string]bool
 exception map[string]bool
}

var pslOnce sync.Once
var pslData suffixRules

func parseSuffixRules(data string)suffixRules{
 rules:=suffixRules{
  exact:map[string]bool{},
  wildcard:map[string]bool{},
  exception:map[string]bool{},
 }
 scanner:=bufio.NewScanner(strings.NewReader(data))
 for scanner.Scan(){
  line:=strings.TrimSpace(scanner.Text())
  if line==""||strings.HasPrefix(line,"//"){continue}
  line=strings.ToLower(line)
  switch {
  case strings.HasPrefix(line,"!"):
   rules.exception[encodeSuffixASCII(strings.TrimPrefix(line,"!"))]=true
  case strings.HasPrefix(line,"*."):
   rules.wildcard[encodeSuffixASCII(strings.TrimPrefix(line,"*."))]=true
  default:
   rules.exact[encodeSuffixASCII(line)]=true
  }
 }
 return rules
}

func registeredDomain(name string)string{
 pslOnce.Do(func(){pslData=parseSuffixRules(publicSuffixSource)})
 return registeredDomainWithRules(strings.TrimSuffix(strings.ToLower(name),"."),pslData)
}

// registeredDomainWithRules returns the registrable domain (eTLD+1), or an
// empty string when input itself is a public suffix. A default "*" rule
// applies to unknown suffixes. Only ASCII/Punycode hostnames reach this path.
func registeredDomainWithRules(name string,rules suffixRules)string{
 labels:=strings.Split(name,".")
 if len(labels)<2{return ""}
 best:=1
 exception:=0
 for i:=0;i<len(labels);i++{
  suffix:=strings.Join(labels[i:],".")
  count:=len(labels)-i
  if rules.exception[suffix]&&count>exception{exception=count}
  if rules.exact[suffix]&&count>best{best=count}
  if i>0&&rules.wildcard[suffix]&&count+1>best{best=count+1}
 }
 if exception>0{best=exception-1}
 if len(labels)<=best{return ""}
 return strings.Join(labels[len(labels)-best-1:],".")
}
func domainTargets(name string)[]string{
 name=strings.TrimSuffix(strings.ToLower(name),".")
 apex:=registeredDomain(name)
 if apex!=""&&name==apex{return []string{name,"www."+name}}
 return []string{name}
}
