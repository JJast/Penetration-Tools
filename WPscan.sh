#!/bin/bash

while getopts o:i: flag
do
    case "${flag}" in
        o) output=${OPTARG};;
        i) input=${OPTARG};;
    esac
done

echo "Disclaimer: Run WPscan with ADMIN privileges"

# Update database
sudo wpscan --update

echo "Start running..."
echo "WordPress Scan List" > "$output"
echo "" >> "$output"

# Specify the file path for API keys
file_path="/home/kali/WP_API"

lines=()

while IFS= read -r line; do
  # Skip empty lines
  if [[ -n "$line" ]]; then
    lines+=("$line")
  fi
done < "$file_path"

# Number of elements
element_count="${#lines[@]}"

# Declare counter
counter=0

while read p; do
    echo " "
    echo "Starting scanning site:"
    echo "$p"
    echo "$p" >> "$output"

    element="${lines[$counter]}"

    # WPscan script
    sudo wpscan --url "$p" --enumerate vp --plugins-detection aggressive --api-token "$element" --disable-tls-checks --force >> "$output"
    
    # Wait for program to end
    wait $!

    counter=$((counter+1))

    # Check if all API keys are used
    if (( "$counter" == "$element_count" )); then
        counter=0
        echo -e "\nRESET\n"
    fi
done < "$input"
echo "Program ended"