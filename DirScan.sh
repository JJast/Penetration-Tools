#!/bin/bash

while getopts o:i: flag
do
    case "${flag}" in
        o) output=${OPTARG};;
        i) input=${OPTARG};;
    esac
done

echo "Start running..."
echo "GoBuster Scan List" > "$output"
echo "" >> "$output"
while read p; do
        echo " "
        echo "Starting scanning site:"
        echo "$p"
        echo "$p" >> "$output"
        sudo gobuster dir -u "$p" -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -k >> "$output"
        wait $!
        echo " " >> "$output"
done < "$input"
echo "Program ended"