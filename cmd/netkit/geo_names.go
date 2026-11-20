package main

import "strings"

// Small curated aliases only: avoid translating an ambiguous city without
// geographic context. Unknown names stay as supplied by the providers.
var regionAliases = map[string]string{
 "california":"California","加利福尼亚州":"California","加州":"California",
 "virginia":"Virginia","弗吉尼亚州":"Virginia",
 "tokyo":"Tokyo","tokyo-to":"Tokyo","東京都":"Tokyo","东京":"Tokyo","東京都":"Tokyo",
 "chiba":"Chiba","chiba prefecture":"Chiba","千葉県":"Chiba","千叶县":"Chiba",
}
var regionChinese = map[string]string{
 "California":"加利福尼亚州","Virginia":"弗吉尼亚州",
 "Tokyo":"东京","Chiba":"千叶县",
}
var cityAliases = map[string]map[string]string{
 "California":{"mountain view":"Mountain View","山景城":"Mountain View",
 "san jose":"San Jose","圣何塞":"San Jose","聖荷西":"San Jose"},
 "Virginia":{"ashburn":"Ashburn","阿什本":"Ashburn"},
 "Tokyo":{"shinjuku":"Shinjuku","新宿":"Shinjuku","新宿区":"Shinjuku",
 "tokyo":"Tokyo","东京":"Tokyo","東京都":"Tokyo"},
 "Chiba":{"chiba":"Chiba","千叶":"Chiba","千葉":"Chiba"},
}
var cityChinese = map[string]map[string]string{
 "California":{"Mountain View":"山景城","San Jose":"圣何塞"},
 "Virginia":{"Ashburn":"阿什本"},
 "Tokyo":{"Shinjuku":"新宿","Tokyo":"东京"},
 "Chiba":{"Chiba":"千叶"},
}

func normalizeRegion(raw string)string {
 raw=strings.TrimSpace(raw)
 if canonical,ok:=regionAliases[strings.ToLower(raw)];ok {return canonical}
 return raw
}
func normalizeCity(region,raw string)string {
 raw=strings.TrimSpace(raw)
 if aliases,ok:=cityAliases[normalizeRegion(region)];ok {
  if canonical,ok:=aliases[strings.ToLower(raw)];ok{return canonical}
 }
 return raw
}
func normalizedLocation(region,city string)(string,string){
 region=normalizeRegion(region)
 return region,normalizeCity(region,city)
}
func displayLocation(loc LocationCandidate,lang string)string{
 region,city:=normalizedLocation(loc.Region,loc.City)
 if lang=="zh" {
  if name,ok:=regionChinese[region];ok {region=name}
  if mapping,ok:=cityChinese[normalizeRegion(loc.Region)];ok {
   if name,ok:=mapping[city];ok {city=name}
  }
 }
 if region=="" {return city}
 if city=="" {return region}
 if strings.EqualFold(region,city) {return city}
 return region+"/"+city
}
func locationLabelsLang(locations []LocationCandidate,lang string)[]string{
 result:=make([]string,0,len(locations))
 for _,loc:=range locations {result=append(result,displayLocation(loc,lang))}
 return result
}
