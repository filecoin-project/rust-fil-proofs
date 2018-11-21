#!/usr/bin/env bash
name=""
samples=""
time=""
slope=""
rsqr=""
mean=""
stddev=""
median=""
medabsdev=""

function as_list {
  out=$(echo $@ | sed "s/ /\", \"/g")
  echo "[\"$out\"]"
}

results=[]
index=0

while IFS= read line; do
  if [[ $line =~ ^Benchmarking ]]; then
    if [[ -z $name ]]; then
      name=`echo "$line" | cut -d' ' -f2-`
    fi
  fi
  if [[ "$line" =~ Collecting ]]; then
    samples=$(echo "$line" | cut -d'C' -f2 | cut -d' ' -f2)
  fi
  if [[ "$line" =~ time: ]]; then
    time=$(echo "$line" | cut -d'[' -f2 | cut -d']' -f1 | awk '{ print $1$2, $3$4, $5$6 }')
  fi
  if [[ "$line" =~ ^slope ]]; then
    slope=$(echo "$line" | cut -d'[' -f2 | cut -d']' -f1 | awk '{ print $1$2, $3$4 }')
    rsqr=$(echo "$line" | cut -d'[' -f3 | cut -d']' -f1 | awk '{ print $1, $2 }')
  fi
  if [[ "$line" =~ ^mean ]]; then
    mean=$(echo "$line" | cut -d'[' -f2 | cut -d']' -f1 | awk '{ print $1$2, $3$4 }')
    stddev=$(echo "$line" | cut -d'[' -f3 | cut -d']' -f1 | awk '{ print $1$2, $3$4 }')
  fi
  if [[ "$line" =~ ^median ]]; then
    median=$(echo "$line" | cut -d'[' -f2 | cut -d']' -f1 | awk '{ print $1$2, $3$4 }')
    medabsdev=$(echo "$line" | cut -d'[' -f3 | cut -d']' -f1 | awk '{ print $1$2, $3$4 }')
    results[index]="  {
    \"name\": "\"$name\"",
    \"samples\": $samples,
    \"time\": $(as_list $time),
    \"slope\": $(as_list $slope),
    \"R^2\": $(as_list $rsqr),
    \"mean\": $(as_list $mean),
    \"std. dev.\": $(as_list $stddev),
    \"median\": $(as_list $median),
    \"med. abs. dev.\": $(as_list $medabsdev)
  }"
    name=""
    index=$((index+1))
  fi
done

count=$((index-1))

if [ "$count" -ge "1" ]; then
  echo "["
  for n in ${!results[@]}; do
    printf "${results[$n]}"
    if [ "$n" -ne "$count" ]; then
      echo ", "
    else
      echo
    fi
  done
  echo "]"
fi
