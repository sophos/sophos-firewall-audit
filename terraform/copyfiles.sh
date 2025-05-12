#!/bin/bash

copy_files() {
    local source="$1"
    local destination="$2"

    # Expand wildcard pattern to get a list of matching files/directories
    local source_files=($source)

    # Check if there are any matches for the wildcard
    if [ ${#source_files[@]} -gt 0 ]; then
        # Loop through each matched file/directory and copy to the destination
        for file in "${source_files[@]}"; do
            if [ -e "$file" ]; then
                cp -r "$file" "$destination"
                echo "$file copied successfully."
            else
                echo "Source '$file' does not exist."
            fi
        done
    else
        echo "No matching files or directories found for source '$source'."
    fi
}

copy_files "$1" "$2"