package main

import "strings"

// encodeSuffixASCII converts Unicode PSL rules to ASCII/Punycode without
// external Go dependencies. NetKit's public CLI accepts ASCII IDNA labels.
// The input PSL is already normalized by its upstream maintainers.
func encodeSuffixASCII(rule string)string{
 labels:=strings.Split(rule,".")
 for i,label:=range labels{
  basic:=true
  for _,c:=range label{if c>=128{basic=false;break}}
  if !basic{labels[i]="xn--"+encodePunycodeLabel(label)}
 }
 return strings.Join(labels,".")
}
func punycodeDigit(n int)byte{
 if n<26{return byte('a'+n)}
 return byte('0'+n-26)
}
func adaptPunycodeBias(delta,numPoints int,first bool)int{
 if first{delta/=700}else{delta/=2}
 delta+=delta/numPoints
 k:=0
 for delta>455{
  delta/=35
  k+=36
 }
 return k+(36*delta)/(delta+38)
}
func encodePunycodeLabel(label string)string{
 codepoints:=[]rune(strings.ToLower(label))
 var out strings.Builder
 basic:=0
 for _,cp:=range codepoints{
  if cp<128 {out.WriteByte(byte(cp));basic++}
 }
 if basic==len(codepoints){return out.String()}
 if basic>0{out.WriteByte('-')}
	n,delta,bias:=128,0,72
	h:=basic
	for h<len(codepoints){
		m:=int(^uint(0)>>1)
		for _,cp:=range codepoints{if int(cp)>=n&&int(cp)<m{m=int(cp)}}
		if m==int(^uint(0)>>1){break}
		delta+=(m-n)*(h+1)
		n=m
		for _,cp:=range codepoints{
			if int(cp)<n{delta++}
			if int(cp)!=n{continue}
			q:=delta
			for k:=36;;k+=36{
				t:=1
				if k>=bias+26{t=26}else if k>bias{t=k-bias}
				if q<t{break}
				out.WriteByte(punycodeDigit(t+(q-t)%(36-t)))
				q=(q-t)/(36-t)
			}
			out.WriteByte(punycodeDigit(q))
			bias=adaptPunycodeBias(delta,h+1,h==basic)
			delta=0
			h++
		}
		delta++
		n++
	}
	return out.String()
}
