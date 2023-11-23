#!/bin/bash

while getopts o:i: flag
do
    case "${flag}" in
        o) output=${OPTARG};;
        i) input=${OPTARG};;
    esac
done

echo "Start running..."
echo "SSLscan Scan List" > "$output"
echo "" >> "$output"
while read p; do
        echo " "
        echo "Starting scanning site:"
        echo "$p"
        echo "$p" >> "$output"
        sudo sslscan "$p" >> "$output"
        wait $!
        echo " " >> "$output"
done < "$input"
echo "Program ended"