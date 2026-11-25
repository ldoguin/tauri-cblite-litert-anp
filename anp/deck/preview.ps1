<#
  Builds a local preview of the deck from its sources: anp/deck/preview.html, every slide stacked at 1920x1080.
  -Shots also renders one PNG per slide into anp/deck/shots with Microsoft Edge (headless).
  An approximation of the real viewer: system fonts instead of the brand fonts, no logo, no arrows between boxes, speaker notes hidden.
#>
param([switch]$Shots)

$here = $PSScriptRoot
$deck = Get-Content (Join-Path $here 'project\deck.json') -Raw | ConvertFrom-Json
$css = Get-Content (Join-Path $here 'project\deck.css') -Raw

# the two pictures a slide holds as stored assets in the artifact, and the files they are here
$assets = @{
  '/_blob/ddbf5208555c0b5dad1427ac334fd0b0' = 'images/control-room.png'
  '/_blob/50120ce562f18ca22e06cd41c3a2deb1' = 'images/fleet.png'
}

# what a slide needs to lay out the way the viewer does, in plain CSS
$base = @'
* { margin: 0 }
body { font: 32px/1.2 "Segoe UI", system-ui, sans-serif; background: #888 }
body > section { width: 1920px; height: 1080px; overflow: hidden; box-sizing: border-box; position: relative; isolation: isolate; margin-bottom: 24px }
aside { display: none }
h1 { font-size: 96px; font-weight: 600 } h2 { font-size: 64px; font-weight: 600 } h3 { font-size: 44px; font-weight: 600 }
p, li, h1, h2, h3, td, th { overflow-wrap: break-word }
table { border-collapse: separate; border-spacing: 0; border: solid #0003; border-width: 2px 0 0 2px }
th, td { padding: .35em .6em; text-align: left; border: solid #0003; border-width: 0 2px 2px 0 }
x-shape, x-icon, x-connector { display: block }
'@

$sections = foreach ($id in $deck.order) {
  $html = Get-Content (Join-Path $here "project\slides\$id.html") -Raw
  foreach ($k in $assets.Keys) { $html = $html.Replace($k, $assets[$k]) }
  $html
}
$page = "<!doctype html><meta charset=utf-8><title>$($deck.title)</title><style>$base`n$css</style><body>`n$($sections -join "`n")`n</body>"
$out = Join-Path $here 'preview.html'
Set-Content -Path $out -Value $page -Encoding UTF8
Write-Host "wrote $out ($($deck.order.Count) slides)"

if ($Shots) {
  $edge = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
  if (-not $edge) { throw 'Microsoft Edge was not found; open preview.html in a browser instead.' }
  $dir = Join-Path $here 'shots'
  New-Item -ItemType Directory -Force $dir | Out-Null
  $i = 0
  foreach ($id in $deck.order) {
    $i++
    $one = Join-Path $dir ('{0:00}-{1}.html' -f $i, $id)
    $sec = (Get-Content (Join-Path $here "project\slides\$id.html") -Raw)
    foreach ($k in $assets.Keys) { $sec = $sec.Replace($k, (Join-Path $here $assets[$k]).Replace('\', '/')) }
    Set-Content -Path $one -Value "<!doctype html><meta charset=utf-8><style>$($base.Replace('margin-bottom: 24px', 'margin-bottom: 0'))`n$css</style><body>$sec</body>" -Encoding UTF8
    $png = [IO.Path]::ChangeExtension($one, 'png')
    # headless Edge sometimes exits without writing the file: try a few times
    foreach ($try in 1..4) {
      & $edge --headless=new --disable-gpu --hide-scrollbars --window-size=1920,1080 "--screenshot=$png" ("file:///" + $one.Replace('\', '/')) 2>$null | Out-Null
      if (Test-Path $png) { break }
      Start-Sleep 2
    }
    if (-not (Test-Path $png)) { Write-Warning "no screenshot for slide $i ($id)" }
    Remove-Item $one
  }
  Write-Host "wrote $i PNGs in $dir"
}
