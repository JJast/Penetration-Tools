#!/bin/bash
echo 'Preparing'
#Trust me, this is necessary. Do not touch, unless you know how to do it better
d=$( date '+%H%M%S' )
mkdir scan$d 2>/dev/null
cd scan$d
rm -r * 2>/dev/null
#You can touch this tho
postfixs=("*conf*" "*cfg*" "*cnf*" "*log*" "*txt*" "*yaml*" "*yml*" "*json*" "*xml*" "*csv*" "*ini*")


echo 'Scanning'
for (( i=0; i<${#postfixs[@]}; i++ ))
do
curr="${postfixs[i]}"
echo $(($i+1)) ' out of ' ${#postfixs[@]}
touch outf
#Feel free to limit the scope
find / -name $curr -type f 2>/dev/null >> outf
#You can change the grep part too
cat outf | xargs awk '{print FILENAME ":" $0}' 2>/dev/null | grep 'pass\|comarch\|haslo\|key\|token' >> out$i
rm outf
done


echo 'Gathering results'
touch credscan.out
for (( i=0; i<${#postfixs[@]}; i++ ))
do
cat out$i >> credscan.out
rm out$i
done
mv credscan.out ..

#find directories to search manually
find / -name "*conf*" -type d 2>/dev/null > outd
find / -name "*cfg*" -type d 2>/dev/null >> outd
find / -name "*cnf*" -type d 2>/dev/null >> outd
mv outd ..
cd ..
rm -r scan$d

#co to się działo ;_;
#postfixs=(".config" ".log" ".txt" ".csv" ".cnf" ".conf" ".ini" ".yml" ".json" ".xml")
#for (( i=0; i<${#postfixs[@]}; i++ ))
#do
# w find do zmiany . na coś rozsądniejszego
#curr="*${postixs[$i]}"
#echo $curr
#find . -type f -name $curr -maxdepth 1 2>/dev/null | xargs cat | grep -E 'password|passcode|haslo|comarch' | xargs echo
# pewnie jeszcze do poprawienia, założe się że nie wyświetla nazwy pliku w którym coś znalazł
#done