powershell -NoExit -NoProfile -ExecutionPolicy Bypass -Command "$file = \"$Env:USERPROFILE\DevSetup.ps1\"; [System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'; Invoke-WebRequest -Uri https://bit.ly/2w0WQVQ -UseBasicParsing -OutFile $file; & $file"