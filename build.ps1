# Build SySscaner.exe: embeds ui.html and compiles scan.cpp (needs g++ from MSYS2/MinGW).
# NOTE: keep this file ASCII-only (Windows PowerShell 5.1 reads BOM-less files as ANSI).
param([string]$Out = 'SySscaner.exe')
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$html = [IO.File]::ReadAllText("$PSScriptRoot\ui.html", [Text.Encoding]::UTF8)
$bad = ')UIHTML' + '"'
if ($html.Contains($bad)) { throw 'ui.html contains a forbidden sequence' }
$header = 'static const char UI_HTML[] = R"UIHTML(' + $html + ')UIHTML";' + "`n"
[IO.File]::WriteAllText("$PSScriptRoot\ui_html.h", $header, (New-Object Text.UTF8Encoding($false)))

$out = $Out
if (Test-Path $out) {
    try { Remove-Item $out -Force } catch { throw "Cannot overwrite $out - close the running scanner first (or use -Out other.exe)." }
}
windres app.rc -O coff -o app.res.o
if ($LASTEXITCODE -ne 0) { throw 'windres failed' }
g++ -std=c++17 -O2 -Wall -Wno-unused-function -finput-charset=UTF-8 -fexec-charset=UTF-8 scan.cpp app.res.o -o $out `
    -static -pthread -lws2_32 -lwintrust -lcrypt32 -ladvapi32 -lshell32 -lole32 -luuid -lbcrypt -liphlpapi
if ($LASTEXITCODE -ne 0) { throw 'Compilation failed' }
Remove-Item app.res.o -Force
Write-Host "Done: $out"
