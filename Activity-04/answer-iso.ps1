$iso = "answer.iso"
$xml = "Autounattend.xml"

if (-Not (Test-Path $xml)) {
    Write-Error "Missing $xml"
    exit 1
}

# Create temporary directory
$tempDir = Join-Path $env:TEMP "AutounattendISO"
Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $tempDir | Out-Null

# Copy the file into that directory
Copy-Item $xml -Destination (Join-Path $tempDir "Autounattend.xml")

# Path to oscdimg
$oscdimg = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"

# Create the ISO
& $oscdimg -u2 -udfver102 -lANS -m $tempDir $iso

Write-Host "✅ Created $iso"

# Optionally clean up
Remove-Item -Recurse -Force $tempDir
