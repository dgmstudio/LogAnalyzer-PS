# ====================================================================
# [ LogAnalyzer-PS: Analizador Forense de Logs Web Híbrido Avanzado ]
# ====================================================================
# Autor: Diego García Merino
# Versión: 1.0.0 FINAL STABLE (Interna V7.02LX)
# Fecha: Noviembre 2025
# 
# Descripción: Herramienta forense de alto rendimiento (WPF/PowerShell) para 
#              el análisis, filtrado y enriquecimiento inteligente de logs de
#              **servidores web** como **Apache, Nginx, IIS, Cloudflare**, etc.
# ESTABILIDAD V7.0: Se han implementado correcciones críticas para la 
#                   estabilidad en modo CLI (Linux) y la validación de la GUI,
#                   asegurando un flujo de trabajo sin errores en ambos entornos.
# Desarrollo Asistido: Modelos LLM (Gemini/GPT) como Co-Piloto de Código.
# 
# CARACTERÍSTICAS DESTACADAS:
# - **Modo Híbrido CLI/GUI:** Soporte para Línea de Comandos (Headless en Linux/macOS) y modo Gráfico y CLI (WPF en Windows).
# - **Análisis Multi-IA:** Integración nativa con Gemini, GPT-4o y Modelos Locales vía Ollama.
# - **Inteligencia CVE Contextual:** Correlación automática de ataques con NVD/NIST y poda inteligente de metadatos JSON.
# - **Threat Intelligence (TI):** Enriquecimiento de IPs con IPInfo.io, AbuseIPDB, VirusTotal y FireHol (Listas negras).
# - **Contribuciones de Threat Intelligence** Identificación de bots,crawlers y scrappers por apache-ultimate-bad-bot-blocker Mitchell Krogza (MIT License)
# - **Sistema de Caché Robusto:** Persistencia de datos de análisis y reputación de IPs para optimizar cuotas de API.
# - **Reportes Avanzados:** Exportación asíncrona a Excel/CSV/JSON y generación de informes de IA en Markdown (.md).
# - **UX Pro:** Interfaz con Modo Oscuro/Claro, gráficas y filtrado dinámico en tiempo real.
# 
# LICENCIA: Business Source License (BSL 1.1)
<#
.SYNOPSIS
    LogAnalyzer-PS V1.0: Analizador Forense Universal (Stable Linux/Win)
.DESCRIPTION
    Herramienta híbrida para análisis forense.
    - Windows: GUI completa + CLI.
    - Linux: Solo CLI (Sin exportación de caché para estabilidad).
    - Features: Spinner Animation, FireHol Auto-Download, IA Contextual.
.PARAMETER LogFile
    Ruta al archivo de log.
.PARAMETER Headless
    Activa el modo sin interfaz gráfica (CLI). Obligatorio en Linux.
.PARAMETER OutputFormat
    Formato de exportación CLI: CSV, JSON, Markdown, All.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$LogFile,

    [switch]$Headless,

    [ValidateSet("Bajo", "Medio", "Alto")]
    [string]$Sensitivity = "Medio",

    [switch]$RunAI,

    [ValidateSet("Gemini", "GPT", "Ollama")]
    [string]$AIModel = "Gemini",

    [ValidateSet("General", "CVE")]
    [string]$AIMode = "General",

    [string]$TargetApp = "",
    [string]$TargetVersion = "",

    [ValidateSet("CSV", "JSON", "Markdown", "All")]
    [string]$OutputFormat = "CSV",

    [string]$OutputDir = ".\Informes"
)

# ====================================================================
# [ LogAnalyzer-PS V7.0 FINAL STABLE ]
# ====================================================================

# ----------------------- 
# 1. DETECCIÓN DE ENTORNO
# -----------------------
$isWindowsCheck = $true
if ($PSVersionTable.PSVersion.Major -ge 6) {
    if ($IsLinux -or $IsMacOS) { $isWindowsCheck = $false }
}
$Global:IsWinEnv = $isWindowsCheck
# Forzar Headless si no estamos en entorno Windows Desktop
if (-not $Global:IsWinEnv -and -not $Headless) { $Headless = $true }

# ----------------------- 
# 2. CONFIGURACIÓN
# -----------------------
$AbuseApiKey = "PON_AQUI_TU_CLAVE"        # <-- Pon tu clave de AbuseIPDB
$VirusTotalApiKey = "PON_AQUI_TU_CLAVE"   # <-- Pon tu clave de VirusTotal (API v3)     
$GeminiApiKey = "PON_AQUI_TU_CLAVE" 
#$AbuseApiKey = "PON_AQUI_TU_CLAVE"       
#$VirusTotalApiKey = "PON_AQUI_TU_CLAVE"  
#$GeminiApiKey = "PON_AQUI_TU_CLAVE" 
$OpenAIApiKey = "PON_AQUI_TU_CLAVE_OPENAI"
$global:OllamaUrl = "http://localhost:11434/api/generate"

$CacheFolder = $PSScriptRoot 
$RegexFile = Join-Path $PSScriptRoot "patterns.json"
$global:FireHolFile = Join-Path $CacheFolder "firehol_level1.netset"
$IconFile = Join-Path $PSScriptRoot "app_icon.ico"

# Cargar ensamblados GUI solo en Windows
if ($Global:IsWinEnv -and -not $Headless) {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName WindowsBase
}

# ====================================================================
# 3. FIX CRÍTICO CIDR
# ====================================================================
if (-not ("CidrFixHelper" -as [type])) {
    try {
        $csharpSource = @'
        using System;
        using System.Net;
        public static class CidrFixHelper {
            public static string ParseCIDRToStrings(string cidr) {
                if (string.IsNullOrEmpty(cidr)) return "0,0"; 
                string[] parts = cidr.Split('/');
                if (parts.Length != 2) return "0,0"; 
                IPAddress ipAddress;
                if (!IPAddress.TryParse(parts[0], out ipAddress)) return "0,0";
                int prefix;
                if (!int.TryParse(parts[1], out prefix)) return "0,0";
                
                if (ipAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return "0,0";

                byte[] ipBytes = ipAddress.GetAddressBytes();
                uint ipAsInt = (uint)ipBytes[0] << 24 | (uint)ipBytes[1] << 16 | (uint)ipBytes[2] << 8 | (uint)ipBytes[3];
                uint mask = prefix == 0 ? 0 : 0xFFFFFFFF << (32 - prefix);
                uint startAsInt = ipAsInt & mask;
                uint endAsInt = startAsInt | ~mask;
                return startAsInt.ToString() + "," + endAsInt.ToString();
            }
        }
'@ 
        if ($PSVersionTable.PSVersion.Major -lt 6) { Add-Type -TypeDefinition $csharpSource -ReferencedAssemblies System.Net } 
        else { Add-Type -TypeDefinition $csharpSource -ErrorAction SilentlyContinue }
    } catch { } 
}

# ====================================================================
# 4. VARIABLES Y PATRONES
# ====================================================================
$pattern_low = '(\.\./|select.*from|union.*select|%3Cscript|%3Ciframe)'
$pattern_med = '(\.\./|\%3Cscript|\%3Ciframe|UNION.*SELECT|SELECT.*FROM|wget |curl |python|urllib|requests|mechanize|scrapy)'
$pattern_high = '(\.\./|%3Cscript|%3Ciframe|%3C|%3E|SELECT.*FROM|UNION.*SELECT|INSERT.*INTO|UPDATE.*SET|DELETE.*FROM|DROP.*TABLE|xp_cmdshell|/etc/passwd|\\win.ini|cmd.exe|wget |curl |python|urllib|requests|mechanize|scrapy|nmap|nikto|sqlmap|bsqlbf|sleep\(|benchmark\()'

if (Test-Path $RegexFile) {
    try {
        $jsonRegex = Get-Content $RegexFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($jsonRegex.low) { $pattern_low = $jsonRegex.low }
        if ($jsonRegex.med) { $pattern_med = $jsonRegex.med }
        if ($jsonRegex.high) { $pattern_high = $jsonRegex.high }
    } catch {}
}

$botPatterns = @("Googlebot","bingbot","Slurp","DuckDuckBot","Baiduspider","YandexBot","Sogou","Exabot","facebookexternalhit","facebot","ia_archiver","python","curl","wget","mechanize","scrapy", "aiohttp")
try { $botPatterns += (Invoke-RestMethod -Uri "https://raw.githubusercontent.com/mitchellkrogza/apache-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents-htaccess.list" -UseBasicParsing -TimeoutSec 3 | ForEach-Object { $_.Trim() }) } catch {}

$global:total = 0; $global:matches = 0
$global:tempData = New-Object System.Collections.Generic.List[object] 
$global:CachedAnalysisData = @{} 
$global:CachedAI = [PSCustomObject]@{ Prompt = ""; Response = "" }
$global:FireHolRanges = @(); $global:FireHolLoaded = $false
if(Test-Path $global:FireHolFile){ $global:FireHolLastUpdate = (Get-Item $global:FireHolFile).LastWriteTime.ToString("yyyy-MM-dd HH:mm") }
$global:CurrentLogFile = ""

# ====================================================================
# 5. FUNCIONES CORE
# ====================================================================

function Invoke-LogParsing {
    param([string]$Path, [string]$Level)
    if(-not (Test-Path $Path)){ return $null }
    $global:CurrentLogFile = $Path
    $localData = New-Object System.Collections.Generic.List[object]
    $pattern = switch ($Level) { "Bajo" {$pattern_low} "Alto" {$pattern_high} Default {$pattern_med} }
    $global:total = 0; $global:matches = 0
    
    # Variables para Spinner
    $spinChars = @('-', '\', '|', '/')
    $spinIndex = 0

    try {
        $reader = [System.IO.File]::OpenText($Path)
        while($null -ne ($line = $reader.ReadLine())){
            $global:total++
            
            # Feedback GUI (Windows)
            if($global:total % 2000 -eq 0 -and $Global:IsWinEnv -and -not $Headless){
                $StatusLabel.Text = "Analizando... Línea $($global:total) | Matches: $($global:matches)"
                [System.Windows.Forms.Application]::DoEvents()
            }

            # Feedback CLI (Spinner)
            if ($Headless -and $global:total % 1000 -eq 0) {
                $char = $spinChars[$spinIndex % 4]
                # Usamos `b (backspace) para sobrescribir el carácter anterior
                Write-Host -NoNewline "`b$char"
                $spinIndex++
            }
            
            if($line.Length -gt 2500){ continue } 
            if($line -match $pattern){
                $global:matches++
                $parts = $line -split ' '
                if($parts.Count -ge 9){
                    $rawIP = $parts[0]
                    $ipStr = if($rawIP -match ":"){ $rawIP.Split(':')[0] } else { $rawIP }
                    $ipStr = "$ipStr".Trim() 

                    $ua = "Desconocido"; if($line -match '"([^"]+)"\s+[^"]+\s+"[^"]+"$'){ $ua = $matches[1] }
                    $cliente = "Usuario/Navegador"; foreach($bot in $botPatterns){ if($ua -match $bot){ $cliente = "Bot ($bot)"; break } }
                    
                    $fechaHoraRaw = ($parts[3]-replace '\[','') + " " + ($parts[4]-replace '\]','')
                    try { $fechaHora = [datetime]::ParseExact($fechaHoraRaw,'dd/MMM/yyyy:HH:mm:ss zzz',[System.Globalization.CultureInfo]::InvariantCulture) } catch { $fechaHora = Get-Date }

                    $obj = [PSCustomObject]@{
                        IP_Limpia = $ipStr 
                        Fecha_Hora = $fechaHora
                        Metodo = ($parts[5] -replace '"','')
                        URL_Atacada = $parts[6]
                        Codigo = $parts[8]
                        Cliente = $cliente
                        UserAgent = $ua
                        RawRequest = $line
                    }
                    $localData.Add($obj)
                }
            }
        }
        $reader.Close()
        return $localData
    } catch { return $null }
}

function Update-CachedData([string]$ip, [string]$field, $value) {
    if (-not $global:CachedAnalysisData.ContainsKey($ip)) { $global:CachedAnalysisData[$ip] = @{} }
    $global:CachedAnalysisData[$ip][$field] = $value
}

function Get-Geo([string]$IP){
    if ($global:CachedAnalysisData[$IP] -and $global:CachedAnalysisData[$IP].Pais) {
         return [PSCustomObject]@{Pais=$global:CachedAnalysisData[$IP].Pais; Ciudad=$global:CachedAnalysisData[$IP].Ciudad}
    }
    try {
        $res = Invoke-RestMethod -Uri "https://ipinfo.io/$IP/json" -UseBasicParsing -TimeoutSec 5
        $obj = [PSCustomObject]@{Pais=$res.country; Ciudad=$res.city}
    } catch { $obj = [PSCustomObject]@{Pais="??"; Ciudad="??"} }
    Update-CachedData $IP "Pais" $obj.Pais; Update-CachedData $IP "Ciudad" $obj.Ciudad
    return $obj
}

function Load-FireHolRanges {
    if ($Global:IsWinEnv -and -not $Headless -and $StatusLabel) { $StatusLabel.Text = "Cargando rangos FireHol..."; [System.Windows.Forms.Application]::DoEvents() }
    
    if(-not (Test-Path $global:FireHolFile)){ return $false }
    
    $tempRanges = @()
    try {
        $lines = Get-Content -Path $global:FireHolFile -Encoding UTF8
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ($trimmed.Length -eq 0 -or $trimmed.StartsWith("#")) { continue }
            if ($trimmed -match '/') {
                 try {
                    $resultString = [CidrFixHelper]::ParseCIDRToStrings($trimmed)
                    $parts = $resultString.Split(',')
                    if($parts.Length -eq 2) { $tempRanges += [PSCustomObject]@{ Start=[uint64]$parts[0]; End=[uint64]$parts[1] } }
                 } catch {}
            }
        }
        $global:FireHolRanges = $tempRanges; $global:FireHolLoaded = $true
        $global:FireHolLastUpdate = (Get-Item $global:FireHolFile).LastWriteTime.ToString("yyyy-MM-dd")
        # === FIX: Actualización del estado en la GUI con el recuento total ===
        if ($Global:IsWinEnv -and -not $Headless -and $StatusLabel) { 
            $count = $tempRanges.Count
            $StatusLabel.Text = "FireHol cargado con éxito: $count rangos."
            [System.Windows.Forms.Application]::DoEvents()
        }
        # ====================================================================
        return $true
    } catch { $global:FireHolLoaded = $false; return $false }
}

function Check-IpFireHol([string]$ip){
    if ($global:CachedAnalysisData[$ip] -and $global:CachedAnalysisData[$ip].FireHolCheck) { return [PSCustomObject]@{ FireHolCheck=$global:CachedAnalysisData[$ip].FireHolCheck } }
    
    if (-not $global:FireHolLoaded) { Load-FireHolRanges | Out-Null }
    $res = "No encontrado"
    if (-not $global:FireHolLoaded) { $res = "N/D" }
    else {
        try {
            $ipObj = [System.Net.IPAddress]::Parse($ip); $bytes = $ipObj.GetAddressBytes()
            if ($bytes.Length -eq 4) {
               $ipInt = ([uint64]$bytes[0] * 16777216) + ([uint64]$bytes[1] * 65536) + ([uint64]$bytes[2] * 256) + ([uint64]$bytes[3])
               foreach ($range in $global:FireHolRanges) {
                   if (($ipInt -ge $range.Start) -and ($ipInt -le $range.End)) { $res = "ENCONTRADO 🔴"; break }
               }
            }
        } catch { $res = "IP Inválida" }
    }
    Update-CachedData $ip "FireHolCheck" $res
    return [PSCustomObject]@{ FireHolCheck = $res }
}

function Update-AbuseInfo([string]$ip){
    if ($global:CachedAnalysisData[$ip] -and $global:CachedAnalysisData[$ip].AbuseScore) {
        return [PSCustomObject]@{ Score=$global:CachedAnalysisData[$ip].AbuseScore; Severidad=$global:CachedAnalysisData[$ip].AbuseSeveridad; Explicacion=$global:CachedAnalysisData[$ip].AbuseExplicacion }
    }
    if($AbuseApiKey -match "PON_AQUI"){ return [PSCustomObject]@{ Score="N/A"; Severidad="Sin Key"; Explicacion="" } }
    try {
        $uri = "https://api.abuseipdb.com/api/v2/check?ipAddress=$($ip.Trim())&maxAgeInDays=90&verbose"
        $headers = @{ "Key" = $AbuseApiKey; "Accept" = "application/json" }
        $resp = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -TimeoutSec 10
        if($resp.data){
            $score = [int]$resp.data.abuseConfidenceScore
            $scText = "$score%"
            $sev = if($score -ge 80){"CRÍTICA 🚨"}elseif($score -ge 50){"ALTA ⚠️"}elseif($score -ge10){"MEDIA 🛑 "}else{"BAJA ✅"}
            $expl = "Rpts: $($resp.data.totalReports), Tipo: $($resp.data.usageType)"
            Update-CachedData $ip "AbuseScore" $scText; Update-CachedData $ip "AbuseSeveridad" $sev; Update-CachedData $ip "AbuseExplicacion" $expl
            return [PSCustomObject]@{ Score=$scText; Severidad=$sev; Explicacion=$expl }
        }
    } catch {}
    return [PSCustomObject]@{ Score="Err"; Severidad=""; Explicacion="" }
}

function Update-VirusTotalInfo([string]$ip){
     if ($global:CachedAnalysisData[$ip] -and $global:CachedAnalysisData[$ip].VT_Check) {
        return [PSCustomObject]@{ VT_Check=$global:CachedAnalysisData[$ip].VT_Check; VT_Explicacion=$global:CachedAnalysisData[$ip].VT_Explicacion }
    }
    if($VirusTotalApiKey -match "PON_AQUI"){ return [PSCustomObject]@{ VT_Check="Sin Key"; VT_Explicacion="" } }
    try {
        $uri = "https://www.virustotal.com/api/v3/ip_addresses/$ip"
        $headers = @{ "x-apikey" = $VirusTotalApiKey }
        $resp = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -TimeoutSec 10
        if($resp.data.attributes.last_analysis_stats){
            $stats = $resp.data.attributes.last_analysis_stats
            $mal = $stats.malicious; $susp = $stats.suspicious; $harm = $stats.harmless
            $resTxt = "Limpia ✅ ($harm)"
            if($mal -gt 0) { $resTxt = "Maliciosa 🚨 ($mal)" }
            elseif($susp -gt 0) { $resTxt = "Sospechosa ⚠️ ($susp)" }
            
            $owner = $resp.data.attributes.as_owner
            $expl = "M:$mal, S:$susp, H:$harm. Propietario: $owner" 
            
            Update-CachedData $ip "VT_Check" $resTxt; Update-CachedData $ip "VT_Explicacion" $expl
            return [PSCustomObject]@{ VT_Check=$resTxt; VT_Explicacion=$expl }
        }
    } catch {}
    return [PSCustomObject]@{ VT_Check="Err"; VT_Explicacion="" }
}

function Get-NvdCveData {
    $CPE = "cpe:2.3:a:$($global:TargetApp):$($global:TargetApp):$($global:TargetVersion):*:*:*:*:*:*:*"
    $NvdUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=$CPE"
    try { return (Invoke-RestMethod -Uri $NvdUrl -Method Get -TimeoutSec 20) } catch { return $null }
}

function Invoke-AI-Provider {
    param($Prompt, $ModelName)
    try {
        if($ModelName -match "Gemini"){
            if ($GeminiApiKey -match "PON_AQUI") { throw "Clave Gemini no configurada." }
            $url="https://generativelanguage.googleapis.com/v1/models/gemini-2.5-flash:generateContent?key=$GeminiApiKey"
            $body=@{contents=@(@{parts=@(@{text=$Prompt})})} | ConvertTo-Json -Depth 4
            $r = Invoke-RestMethod -Uri $url -Method Post -Body $body -ContentType "application/json" -TimeoutSec 60
            return $r.candidates[0].content.parts[0].text
        } elseif ($ModelName -match "GPT") {
             if ($OpenAIApiKey -match "PON_AQUI") { throw "Clave OpenAI no configurada." }
             $url = "https://api.openai.com/v1/chat/completions"
             $headers = @{ "Authorization" = "Bearer $OpenAIApiKey" }
             $body = @{ model = "gpt-4o"; messages = @(@{ role = "user"; content = $Prompt }); max_tokens = 4000 } | ConvertTo-Json -Depth 4
             $r = Invoke-RestMethod -Uri $url -Method Post -Body $body -Headers $headers -ContentType "application/json" -TimeoutSec 60
             return $r.choices[0].message.content
        } else {
            $ollamaModel = ($ModelName -split " " | Select-Object -First 2) -join "" -replace "[()]" 
            if($ollamaModel -match 'Llama3'){ $ollamaModel = 'llama3' }
            if($ollamaModel -match 'Mistral'){ $ollamaModel = 'mistral' } 
            $body=@{model=$ollamaModel;prompt=$Prompt;stream=$false} | ConvertTo-Json
            $r = Invoke-RestMethod -Uri $global:OllamaUrl -Method Post -Body $body -ContentType "application/json" -TimeoutSec 90
            return $r.response
        }
    } catch { return "Error IA: $($_.Exception.Message)" }
}

# ====================================================================
# 6. FUNCIONES DE EXPORTACIÓN
# ====================================================================

function Export-Collection-ToExcel($collection, $filename){
    if (-not $Global:IsWinEnv) { return } 
    $collection = @($collection)
    if($collection.Count -eq 0){ return }
    $payload = ($collection | ConvertTo-Json -Depth 3)
    
    $job = Start-Job -ScriptBlock {
        param($payload,$filename)
        [System.Threading.Thread]::CurrentThread.ApartmentState = [System.Threading.ApartmentState]::STA
        $items = ConvertFrom-Json $payload
        if ($items.Count -eq 0) { return }
        
        try {
            $excel = New-Object -ComObject Excel.Application; $excel.Visible = $false
            $wb = $excel.Workbooks.Add(); $ws = $wb.Worksheets.Item(1)
            $r = 1; $c = 1
            $items[0].PSObject.Properties | ForEach-Object { $ws.Cells.Item($r,$c)=$_.Name; $c++ }
            $r=2
            foreach($it in $items){
                $c=1; 
                $it.PSObject.Properties | ForEach-Object { 
                    $val = $_.Value; 
                    if ($val -is [string] -and $val -match '^\d{4}-\d{2}-\d{2}T') { try { $val = [datetime]::Parse($val) } catch {} }
                    $ws.Cells.Item($r,$c)=$val; $c++ 
                }
                $r++
            }
            $ws.Columns.AutoFit(); $wb.SaveAs($filename); $wb.Close($true); $excel.Quit()
        } catch {}
    } -ArgumentList $payload,$filename 
    return $job
}

function Export-Collection-ToCsv($collection, $filename){
    try { @($collection) | Export-Csv -Path $filename -NoTypeInformation -Encoding UTF8; return $true } catch { return $false }
}

function Export-Collection-ToJson($collection, $filename){
    $payload = @($collection) | ConvertTo-Json -Depth 4
    Set-Content -Path $filename -Value $payload -Encoding UTF8
}

# FUNCIÓN EXPORTAR CACHÉ (Segura)
function Export-Cache-ToJson($data, $enriched, $ai, $filename){
    # En Linux, omitir si se detecta problema de tipo, o convertir.
    # Para V7.0, asumimos que la conversión compleja falla en Linux y la omitimos selectivamente si es CLI Linux.
    
    $cleanEnriched = New-Object 'System.Collections.Generic.Dictionary[string,object]'
    if ($enriched) {
        foreach($ipKey in $enriched.Keys) {
            $ipDataHashtable = $enriched[$ipKey]
            $cleanIpData = New-Object 'System.Collections.Generic.Dictionary[string,object]'
            if ($ipDataHashtable) {
                foreach($fieldKey in $ipDataHashtable.Keys) {
                    $cleanIpData[[string]$fieldKey] = $ipDataHashtable[$fieldKey]
                }
            }
            $cleanEnriched[[string]$ipKey] = $cleanIpData
        }
    }
    
    $cleanData = @($data) 

    $export = [PSCustomObject]@{ 
        MetaData = [PSCustomObject]@{ TotalLines = $global:total; Matches = $global:matches; LogFile = $global:CurrentLogFile }
        Data = $cleanData 
        Enriched = $cleanEnriched
        AI = $ai
    }
    
    $payload = $export | ConvertTo-Json -Depth 10 
    Set-Content -Path $filename -Value $payload -Encoding UTF8
}

# ====================================================================
# 7. EJECUCIÓN CLI (HEADLESS)
# ====================================================================
if ($Headless) {
    Write-Host "[*] LogAnalyzer-PS V1.0 (CLI Mode)" -ForegroundColor Cyan
    
    if (-not (Test-Path $LogFile)) { Write-Error "Log no encontrado: $LogFile"; exit 1 }
    if ($AIMode -eq "CVE" -and ($RunAI) -and (-not $TargetApp -or -not $TargetVersion)) {
        Write-Error "Modo CVE requiere -TargetApp y -TargetVersion"; exit 1
    }

    Write-Host " -> Analizando... " -NoNewline
    $global:tempData = Invoke-LogParsing -Path $LogFile -Level $Sensitivity
    
    if ($global:tempData.Count -eq 0) { Write-Warning "No hay datos."; exit }
    # Sobrescribir el spinner con el resultado final
    Write-Host "`bHECHO ($($global:tempData.Count) matches / $($global:total) total lines)" -ForegroundColor Green

    # Descarga automática de FireHol en CLI si falta
    if (-not $global:FireHolLoaded) { 
        if (-not (Test-Path $global:FireHolFile)) {
             Write-Host " -> Descargando FireHol (Automático)..." -NoNewline
             try { Invoke-WebRequest -Uri "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset" -OutFile $global:FireHolFile -UseBasicParsing; Write-Host " OK." -ForegroundColor Green } catch { Write-Host " Error." -ForegroundColor Red }
        }
        Load-FireHolRanges | Out-Null 
    }

    $ipGroups = $global:tempData | Group-Object IP_Limpia
    $totalIPs = $ipGroups.Count
    Write-Host " -> Enriqueciendo $totalIPs IPs..."
    
    $i=0
    $ipGroups | ForEach-Object { 
        $i++
        if($i % 10 -eq 0){ Write-Host " -> Progreso de enriquecimiento: $i de $totalIPs" -ForegroundColor Yellow }

        Get-Geo $_.Name | Out-Null
        Check-IpFireHol $_.Name | Out-Null
        Update-AbuseInfo $_.Name | Out-Null
        Update-VirusTotalInfo $_.Name | Out-Null
    }
    Write-Host " -> Enriquecimiento completado." -ForegroundColor Green

    $aiReport = ""
    if ($RunAI) {
        Write-Host " -> Consultando IA ($AIModel)..." -NoNewline
        $topIPs = ($global:tempData | Group-Object IP_Limpia | Sort-Object Count -Descending | Select-Object -First 5).Name -join ", "
        $topUrls = ($global:tempData | Group-Object URL_Atacada | Sort-Object Count -Descending | Select-Object -First 5).Name -join "`n"
        $topUAs = ($global:tempData | Group-Object UserAgent | Sort-Object Count -Descending | Select-Object -First 8) | ForEach-Object { "UA: $($_.Name) | Req: $($_.Count)" }
        
        $dateInfo = Get-Date -Format "yyyy-MM-dd"
        $prompt = "FECHA ACTUAL: $dateInfo\nROL: Analista de Seguridad nivel 3. Analiza este log de Apache. \n" +
              "RESUMEN:\nTotal Peticiones: $global:total\nMatches Sospechosos: $global:matches\n" +
              "[Top 5 IPs Atacantes]\n" + ($topIPs -join "`n") + "\n" +
              "[Top 10 URLs Atacadas]\n" + ($topUrls -join "`n") + "\n" +
              "[Top User Agents]\n" + ($topUAs -join "`n")
        
        if ($AIMode -eq "CVE") {
            $global:TargetApp = $TargetApp; $global:TargetVersion = $TargetVersion
            $nvd = Get-NvdCveData; 
            $PrunedCVEs = @()
            $severityMap = @{ "CRITICAL"=4; "HIGH"=3; "MEDIUM"=2; "LOW"=1; "NONE"=0; "N/A"=0 }

            if ($nvd -and $nvd.vulnerabilities) {
                $nvd.vulnerabilities | Sort-Object { 
                    $s = "N/A"; $m = $_.cve.metrics
                    if ($m.cvssMetricV31) { $s = $m.cvssMetricV31[0].cvssData.baseSeverity }
                    elseif ($m.cvssMetricV30) { $s = $m.cvssMetricV30[0].cvssData.baseSeverity }
                    elseif ($m.cvssMetricV2) { 
                        $sc = $m.cvssMetricV2[0].cvssData.baseScore
                        if($sc -ge 9.0){$s="CRITICAL"} elseif($sc -ge 7.0){$s="HIGH"} elseif($sc -ge 4.0){$s="MEDIUM"} else{$s="LOW"}
                    }
                    return $severityMap[$s]
                } -Descending | Select-Object -First 10 | ForEach-Object {
                    $cveItem = $_.cve; $m = $cveItem.metrics
                    $sev = "N/A"; $vec = "N/A"; $exp = "N/A"; $imp = "N/A"
                    
                    $metric = $null
                    if($m.cvssMetricV31){ 
                        $metric = $m.cvssMetricV31 | Where-Object {$_.source -match "nvd"} | Select-Object -First 1
                        if(-not $metric){$metric=$m.cvssMetricV31[0]}
                    }
                    elseif($m.cvssMetricV30){ 
                        $metric = $m.cvssMetricV30 | Where-Object {$_.source -match "nvd"} | Select-Object -First 1
                        if(-not $metric){$metric=$m.cvssMetricV30[0]}
                    }
                    elseif($m.cvssMetricV2){ $metric=$m.cvssMetricV2[0] }
                    
                    if ($metric) {
                        if($metric.cvssData.baseSeverity){ $sev=$metric.cvssData.baseSeverity; $vec=$metric.cvssData.attackVector }
                        elseif($metric.cvssData.baseScore){ $sev="V2 Score " + $metric.cvssData.baseScore; $vec=$metric.cvssData.accessVector }
                        if ($metric.exploitabilityScore) { $exp=$metric.exploitabilityScore }
                        if ($metric.impactScore) { $imp=$metric.impactScore }
                    }
                    $desc = $cveItem.descriptions[0].value
                    $PrunedCVEs += [PSCustomObject]@{ CVE_ID=$cveItem.id; Severidad=$sev; VectorAtaque=$vec; ExploitScore=$exp; ImpactScore=$imp; Descripcion=$desc }
                }
            }
            $prompt += "\n\nCONTEXTO CVE: App: $($global:TargetApp) v$($global:TargetVersion).\n" + 
                       "Vulnerabilidades (JSON Podado): " + ($PrunedCVEs | ConvertTo-Json -Depth 2 | Out-String)
        }
        $aiReport = Invoke-AI-Provider -Prompt $prompt -ModelName $AIModel
        $global:CachedAI.Prompt = $prompt
        $global:CachedAI.Response = $aiReport
        Write-Host " HECHO." -ForegroundColor Green
    }

    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }
    $ts = Get-Date -Format "yyyyMMdd_HHmm"
    $base = Join-Path $OutputDir "LogAnalysis_Export_CLI_$ts"
    
    $dataToExport = $global:tempData | Select-Object IP_Limpia, Fecha_Hora, Metodo, URL_Atacada, Codigo, Cliente, UserAgent, RawRequest

    if ($OutputFormat -match "CSV|All") { Write-Host " -> Exportando CSV..." -NoNewline; Export-Collection-ToCsv $dataToExport "$base.csv" | Out-Null; Write-Host " HECHO." -ForegroundColor Green }
    if ($OutputFormat -match "JSON|All") { Write-Host " -> Exportando JSON (Datos)..." -NoNewline; Export-Collection-ToJson $dataToExport "$base.json"; Write-Host " HECHO." -ForegroundColor Green }
    
    if ($OutputFormat -match "JSON|All" -or $OutputFormat -match "CSV|All") { 
        Write-Host " -> Exportando JSON (Caché)..." -NoNewline
        
        # FIX V7.0: Omitir exportación de caché si estamos en LINUX (CLI) para evitar error.
        if ($Global:IsWinEnv) {
            try {
                 Export-Cache-ToJson $global:tempData $global:CachedAnalysisData $global:CachedAI (Join-Path $OutputDir "LogAnalysis_Cache_$ts.json")
                 Write-Host " HECHO." -ForegroundColor Green 
            } catch {
                 Write-Host " ERROR." -ForegroundColor Red
            }
        } else {
            Write-Host " OMITIDO (Solo Windows)." -ForegroundColor DarkGray
        }
    }
    
    if ($RunAI -and ($OutputFormat -match "Markdown|All")) { Write-Host " -> Exportando Markdown (IA)..." -NoNewline; Set-Content "$base.md" $aiReport -Encoding UTF8; Write-Host " HECHO." -ForegroundColor Green }

    Write-Host "[OK] Resultados en: $OutputDir" -ForegroundColor Green
    exit
}

# ====================================================================
# 8. EJECUCIÓN GUI (WPF - Windows Only)
# ====================================================================
if ($Global:IsWinEnv -and -not $Headless) {

    [xml]$xaml = @"
    <Window xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'
            xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml'
            Title='LogAnalyzer-PS V1.0 FINAL STABLE' Height='850' Width='1300' WindowStartupLocation='CenterScreen'>
      <Grid Margin='8'>
        <Grid.RowDefinitions><RowDefinition Height='Auto'/><RowDefinition Height='Auto'/><RowDefinition Height='Auto'/><RowDefinition Height='*'/><RowDefinition Height='Auto'/></Grid.RowDefinitions>

        <Grid Grid.Row='0'>
            <Grid.ColumnDefinitions><ColumnDefinition Width='*'/><ColumnDefinition Width='Auto'/></Grid.ColumnDefinitions>
            <TextBlock Grid.Column='0' Text='LogAnalyzer-PS V1.0 (Hybrid)' FontSize='20' FontWeight='Bold' Margin='4' />
            <StackPanel Grid.Column='1' Orientation='Horizontal' VerticalAlignment='Center'>
                 <TextBlock Text='Tema:' VerticalAlignment='Center' Margin='5'/>
                 <ComboBox x:Name='ThemeSelector' Width='100' SelectedIndex='0'><ComboBoxItem Content='Claro'/><ComboBoxItem Content='Oscuro'/></ComboBox>
            </StackPanel>
        </Grid>

        <Grid Grid.Row='1' Margin='0,6,0,8'>
          <Grid.ColumnDefinitions><ColumnDefinition Width='Auto' /><ColumnDefinition Width='*' /><ColumnDefinition Width='Auto' /></Grid.ColumnDefinitions>
          <TextBlock Grid.Column='0' VerticalAlignment='Center' Text='Archivo Log:' Margin='4'/>
          <TextBox x:Name='LogPathTextBox' Grid.Column='1' Height='26' Margin='4' Text='.\apache.log'/>
          <Button x:Name='BrowseLogButton' Grid.Column='2' Width='110' Height='26' Margin='4' Content='Buscar Log...' Background='#007ACC' Foreground='White'/>
        </Grid>

        <StackPanel Grid.Row='2' Orientation='Horizontal' HorizontalAlignment='Left' VerticalAlignment='Top' Margin='4'>
          <Button x:Name='StartButton' Width='140' Height='34' Content='▶ Iniciar Análisis' Background='#FFC107' Foreground='#333' FontWeight='Bold' Margin='4'/>
          <Button x:Name='ClearButton' Width='80' Height='34' Content='Limpiar' Background='#DDDDDD' Foreground='#333' Margin='4'/>
          <TextBlock Text='Nivel:' VerticalAlignment='Center' Margin='10,0,5,0'/>
          <ComboBox x:Name='RegexLevelComboBox' Width='80' Height='30' VerticalAlignment='Center' SelectedIndex='1' Padding='5'>
              <ComboBoxItem Content='Bajo'/><ComboBoxItem Content='Medio'/><ComboBoxItem Content='Alto'/>
          </ComboBox>
          <Button x:Name='ExportMenuButton' Width='90' Height='34' Content='Exportar ▾' Background='#4CAF50' Foreground='White' FontWeight='Bold' Margin='4,0,4,4'/>
          <Button x:Name='CacheMenuButton' Width='90' Height='34' Content='Caché ▾' Background='#9E9E9E' Foreground='White' Margin='4'/>
          <Button x:Name='AbuseCheckButton' Width='130' Height='34' Content='Check AbuseIPDB' Background='#E91E63' Foreground='White' Margin='4'/>
          <Button x:Name='VirusTotalCheckButton' Width='130' Height='34' Content='Check VirusTotal' Background='#795548' Foreground='White' Margin='4'/>
          <Button x:Name='FireHolMenuButton' Width='100' Height='34' Content='FireHol ▾' Background='#FF5722' Foreground='White' Margin='4'/> 
          <TextBlock Text='IA:' VerticalAlignment='Center' Margin='10,0,5,0'/>
          <ComboBox x:Name='LLMSelector' Width='160' Height='30' VerticalAlignment='Center' SelectedIndex='0' Padding='5'>
              <ComboBoxItem Content='Gemini 2.5 Flash'/><ComboBoxItem Content='GPT-4o (OpenAI)'/><ComboBoxItem Content='Llama 3 (Local)'/><ComboBoxItem Content='Mistral (Local)'/><ComboBoxItem Content='Phi-3 (Local)'/>
          </ComboBox>
          <TextBlock x:Name='ProcessingIndicator' Text='🛑 PROCESANDO...' VerticalAlignment='Center' Margin='10,0,0,0' Foreground='Red' FontWeight='Bold' Visibility='Collapsed'/>
        </StackPanel>

        <TabControl Grid.Row='3' x:Name='TabControl1' Margin='0,8,0,8'>
          <TabItem Header='1. Resultados Crudos'>
            <Grid>
              <Grid.RowDefinitions><RowDefinition Height='Auto'/><RowDefinition Height='*'/></Grid.RowDefinitions>
              <TextBox x:Name='Filter1' Grid.Row='0' Margin='6' Padding='4' Text='Filtro...'/>
              <DataGrid x:Name='ResultsDataGrid' Grid.Row='1' Margin='6' AutoGenerateColumns='True' IsReadOnly='True'/>
            </Grid>
          </TabItem>
          <TabItem Header='2. Agrupación IP+Geo'>
            <Grid>
              <Grid.RowDefinitions><RowDefinition Height='Auto'/><RowDefinition Height='*'/></Grid.RowDefinitions>
              <TextBox x:Name='Filter2' Grid.Row='0' Margin='6' Padding='4' Text='Filtro...'/>
              <DataGrid x:Name='IpGroupingDataGrid' Grid.Row='1' Margin='6' AutoGenerateColumns='True' IsReadOnly='True' />
            </Grid>
          </TabItem>
          <TabItem Header='3. Frecuencia'>
             <Grid>
              <Grid.RowDefinitions><RowDefinition Height='Auto'/><RowDefinition Height='*'/></Grid.RowDefinitions>
              <TextBox x:Name='Filter3' Grid.Row='0' Margin='6' Padding='4' Text='Filtro...'/>
              <Grid Grid.Row='1'>
                <Grid.ColumnDefinitions><ColumnDefinition Width='2*' /><ColumnDefinition Width='3*' /></Grid.ColumnDefinitions>
                <DataGrid x:Name='TimeGroupingDataGrid' Grid.Column='0' Margin='6' AutoGenerateColumns='True' IsReadOnly='True' />
                <Border Grid.Column='1' Margin='6' BorderBrush='LightGray' BorderThickness='1' CornerRadius='2'>
                  <Image x:Name='TimeChartImage' Stretch='Uniform' Margin='4' />
                </Border>
              </Grid>
            </Grid>
          </TabItem>
          
          <TabItem Header='4. URL Atacada'>
             <Grid>
              <Grid.RowDefinitions><RowDefinition Height='Auto'/><RowDefinition Height='*'/></Grid.RowDefinitions>
              <TextBox x:Name='Filter4' Grid.Row='0' Margin='6' Padding='4' Text='Filtro...'/>
              <DataGrid x:Name='UrlGroupingDataGrid' Grid.Row='1' Margin='6' IsReadOnly='True'/>
             </Grid>
          </TabItem>
          
          <TabItem Header='5. User-Agent'>
             <Grid>
              <Grid.RowDefinitions><RowDefinition Height='Auto'/><RowDefinition Height='*'/></Grid.RowDefinitions>
              <TextBox x:Name='Filter5' Grid.Row='0' Margin='6' Padding='4' Text='Filtro...'/>
              <DataGrid x:Name='UserAgentGroupingDataGrid' Grid.Row='1' Margin='6' IsReadOnly='True'/>
             </Grid>
          </TabItem>

          <TabItem Header='6. Análisis IA y CVE' x:Name='TabAI'>
            <Grid>
                <Grid.RowDefinitions><RowDefinition Height='Auto'/><RowDefinition Height='*'/><RowDefinition Height='Auto'/><RowDefinition Height='2*'/></Grid.RowDefinitions>
                <Border Grid.Row='0' BorderBrush='LightGray' BorderThickness='1' Margin='5' Padding='5' Background='#FAFAFA'>
                    <StackPanel Orientation='Vertical'>
                        <TextBlock Text='Configuración NVD/CVE' FontWeight='Bold' Margin='5'/>
                        <StackPanel Orientation='Horizontal' Margin='0,0,0,5'>
                            <TextBlock Text='Software:' VerticalAlignment='Center' Margin='5'/><TextBox x:Name='AppInput' Width='150' ToolTip='Ej: prestashop'/>
                            <TextBlock Text='Versión:' VerticalAlignment='Center' Margin='15,0,5,0'/><TextBox x:Name='VersionInput' Width='100' ToolTip='Ej: 1.8.2'/>
                        </StackPanel>
                        <StackPanel Orientation='Horizontal' Margin='0,5,0,0'>
                             <Button x:Name='BtnRequestAI' Content='1. Análisis Genérico IA' Margin='5' Padding='15,5' Background='#2196F3' Foreground='White'/>
                             <Button x:Name='BtnRequestCVE' Content='2. Análisis CVE + IA' Margin='5' Padding='15,5' Background='#673AB7' Foreground='White' FontWeight='Bold'/>
                        </StackPanel>
                    </StackPanel>
                </Border>
                <GroupBox Header='Prompt' Grid.Row='1' Margin='10'><TextBox x:Name='TxtPromptAI' TextWrapping='Wrap' IsReadOnly='True' Background='#FFFFFF' FontFamily='Consolas' VerticalScrollBarVisibility='Auto'/></GroupBox>
                <GridSplitter Grid.Row='2' Height='5' HorizontalAlignment='Stretch' Background='Gray'/>
                <GroupBox Header='Respuesta IA' Grid.Row='3' Margin='10'>
                    <Grid>
                        <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                        <StackPanel Grid.Row="0" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,0,0,5">
                            <Button x:Name="BtnExportMarkdown" Content="Exportar .MD" Width="110" Height="26" Background="#1E88E5" Foreground="White" FontWeight="SemiBold"/>
                        </StackPanel>
                        <TextBox x:Name='TxtResponseAI' Grid.Row="1" TextWrapping='Wrap' IsReadOnly='True' Background='#F0F0F0' FontSize='14' VerticalScrollBarVisibility='Auto'/>
                    </Grid>
                </GroupBox>
            </Grid>
          </TabItem>
        </TabControl>

        <StatusBar Grid.Row='4' Background='#F3F3F3'>
          <StatusBarItem><TextBlock x:Name='CountLabel' Text='Resultados: 0' FontWeight='SemiBold'/></StatusBarItem>
          <StatusBarItem><TextBlock x:Name='StatusLabel' Text='Listo' Margin='10,0,0,0'/></StatusBarItem>
          <StatusBarItem HorizontalAlignment='Right'><TextBlock x:Name='CacheLabel' Text='Cache: Ninguna' FontWeight='SemiBold'/></StatusBarItem>
          <StatusBarItem HorizontalAlignment='Right'><TextBlock x:Name='FileMd5Label' Text='' FontWeight='SemiBold'/></StatusBarItem>
        </StatusBar>
      </Grid>
    </Window>
"@

    $reader = (New-Object System.Xml.XmlNodeReader $xaml)
    try { $window = [System.Windows.Markup.XamlReader]::Load($reader) } catch { [System.Windows.Forms.MessageBox]::Show("Error XAML: $($_.Exception.Message)"); return }

    if (Test-Path $IconFile) { try { $window.Icon = [System.Windows.Media.Imaging.BitmapFrame]::Create($IconFile) } catch {} }

    $controls = @("LogPathTextBox","BrowseLogButton","StartButton","ClearButton","ExportMenuButton","CacheMenuButton","AbuseCheckButton","FireHolMenuButton","VirusTotalCheckButton","RegexLevelComboBox","ResultsDataGrid","IpGroupingDataGrid","TimeGroupingDataGrid","UrlGroupingDataGrid","UserAgentGroupingDataGrid","StatusLabel","CountLabel","TabControl1","CacheLabel","ProcessingIndicator","Filter1","Filter2","Filter3","Filter4","Filter5","ThemeSelector","LLMSelector","BtnRequestAI","BtnRequestCVE","TxtPromptAI","TxtResponseAI","AppInput","VersionInput","FileMd5Label","TimeChartImage","BtnExportMarkdown")
    foreach ($c in $controls) { Set-Variable -Name $c -Value ($window.FindName($c)) }

    # MENÚS
    $ctxExport = New-Object System.Windows.Controls.ContextMenu
    $miExpExcel = New-Object System.Windows.Controls.MenuItem -Property @{ Header = "Exportar a Excel (.xlsx)" }
    $miExpCsv = New-Object System.Windows.Controls.MenuItem -Property @{ Header = "Exportar a CSV (.csv)" }
    $miExpJson = New-Object System.Windows.Controls.MenuItem -Property @{ Header = "Exportar a JSON (.json)" }
    $ctxExport.Items.Add($miExpExcel); $ctxExport.Items.Add($miExpCsv); $ctxExport.Items.Add($miExpJson)
    $ExportMenuButton.ContextMenu = $ctxExport 

    $ctxCache = New-Object System.Windows.Controls.ContextMenu
    $miCacheView = New-Object System.Windows.Controls.MenuItem -Property @{ Header = "Ver Cache de IPs (JSON)" }
    $miCacheLoad = New-Object System.Windows.Controls.MenuItem -Property @{ Header = "Cargar Cache de Archivo..." }
    $miCacheSave = New-Object System.Windows.Controls.MenuItem -Property @{ Header = "Guardar Cache a Archivo..." }
    $ctxCache.Items.Add($miCacheView); $ctxCache.Items.Add($miCacheLoad); $ctxCache.Items.Add($miCacheSave)
    $CacheMenuButton.ContextMenu = $ctxCache

    $ctxFireHol = New-Object System.Windows.Controls.ContextMenu
    $miFireHolLoad = New-Object System.Windows.Controls.MenuItem -Property @{ Header = "Cargar Fichero FireHol (Local)" }
    $miFireHolDownload = New-Object System.Windows.Controls.MenuItem -Property @{ Header = "1. Descargar Lista FireHol (Nivel 1)" }
    $miFH_All_Menu = New-Object System.Windows.Controls.MenuItem -Property @{ Header = "2. Comprobar TODO" } 
    $ctxFireHol.Items.Add($miFireHolDownload); $ctxFireHol.Items.Add($miFireHolLoad); $ctxFireHol.Items.Add($miFH_All_Menu)
    $FireHolMenuButton.ContextMenu = $ctxFireHol

    $ctxIP = New-Object System.Windows.Controls.ContextMenu
    $miIPGeo = New-Object System.Windows.Controls.MenuItem -Property @{ Header = "Obtener GEO (ipinfo.io)" }
    $miIPAbuse = New-Object System.Windows.Controls.MenuItem -Property @{ Header = "Check AbuseIPDB (IP Seleccionada)" }
    $miIPVT = New-Object System.Windows.Controls.MenuItem -Property @{ Header = "Check VirusTotal (IP Seleccionada)" }
    $miIPFireHol = New-Object System.Windows.Controls.MenuItem -Property @{ Header = "Check FireHol (IP Seleccionada)" }
    $ctxIP.Items.Add($miIPGeo); $ctxIP.Items.Add($miIPAbuse); $ctxIP.Items.Add($miIPVT); $ctxIP.Items.Add($miIPFireHol)
    $IpGroupingDataGrid.ContextMenu = $ctxIP

    $DataCollection = New-Object System.Collections.ObjectModel.ObservableCollection[object]
    $IpCollection = New-Object System.Collections.ObjectModel.ObservableCollection[object]
    $TimeCollection = New-Object System.Collections.ObjectModel.ObservableCollection[object]
    $UrlCollection = New-Object System.Collections.ObjectModel.ObservableCollection[object]
    $UACollection = New-Object System.Collections.ObjectModel.ObservableCollection[object]

    $DataCollectionFull = New-Object System.Collections.ObjectModel.ObservableCollection[object]
    $IpCollectionFull = New-Object System.Collections.ObjectModel.ObservableCollection[object]
    $TimeCollectionFull = New-Object System.Collections.ObjectModel.ObservableCollection[object]
    $UrlCollectionFull = New-Object System.Collections.ObjectModel.ObservableCollection[object]
    $UACollectionFull = New-Object System.Collections.ObjectModel.ObservableCollection[object]

    $ResultsDataGrid.ItemsSource = $DataCollection
    $IpGroupingDataGrid.ItemsSource = $IpCollection
    $TimeGroupingDataGrid.ItemsSource = $TimeCollection
    $UrlGroupingDataGrid.ItemsSource = $UrlCollection
    $UserAgentGroupingDataGrid.ItemsSource = $UACollection

    # ====================================================================
    # 9. FUNCIONES GUI & HELPERS (V3.6.5 RESTAURADO)
    # ====================================================================

    function Set-Theme {
        param($Theme)
        if ($Theme -eq "Oscuro") {
            $window.Background = (New-Object System.Windows.Media.SolidColorBrush "#222222")
            $window.Foreground = [System.Windows.Media.Brushes]::White
            $LogPathTextBox.Background = (New-Object System.Windows.Media.SolidColorBrush "#444444")
            $LogPathTextBox.Foreground = [System.Windows.Media.Brushes]::White
            $ThemeSelector.Background = (New-Object System.Windows.Media.SolidColorBrush "#444444")
            $ThemeSelector.Foreground = [System.Windows.Media.Brushes]::White
            $TabControl1.Background = (New-Object System.Windows.Media.SolidColorBrush "#222222")
        } else {
            $window.Background = [System.Windows.Media.Brushes]::White
            $window.Foreground = [System.Windows.Media.Brushes]::Black
            $LogPathTextBox.Background = [System.Windows.Media.Brushes]::White
            $LogPathTextBox.Foreground = [System.Windows.Media.Brushes]::Black
            $ThemeSelector.Background = [System.Windows.Media.Brushes]::White
            $ThemeSelector.Foreground = [System.Windows.Media.Brushes]::Black
            $TabControl1.Background = [System.Windows.Media.Brushes]::White
        }
    }

    function Get-CurrentDataGrid {
        switch ($TabControl1.SelectedItem.Header) {
            "1. Resultados Crudos" { return $ResultsDataGrid }
            "2. Agrupación IP+Geo" { return $IpGroupingDataGrid }
            "3. Frecuencia" { return $TimeGroupingDataGrid }
            "4. URL Atacada" { return $UrlGroupingDataGrid }
            "5. User-Agent" { return $UserAgentGroupingDataGrid }
            "6. Análisis IA y CVE" { return [PSCustomObject]@{ IsAI = $true; Prompt = $TxtPromptAI.Text; Response = $TxtResponseAI.Text } }
        }
        return $null
    }

    function Get-VisibleItems($dg){ 
        if($dg -eq $null){ return @() }
        if($dg.IsAI){ return @([PSCustomObject]@{Tipo="Prompt";Text=$dg.Prompt},[PSCustomObject]@{Tipo="Response";Text=$dg.Response}) }
        $res=@(); foreach($i in $dg.ItemsSource){ $res+=$i }; return $res
    }

    function Apply-Filter {
        param($DataGrid, $FullCollection, [string]$FilterText)
        $FilterText = $FilterText.Trim().ToLower()
        
        if ([string]::IsNullOrEmpty($FilterText) -or $FilterText -eq "filtro...") {
            $DataGrid.ItemsSource = $FullCollection
        } else {
            $Filtered = New-Object System.Collections.ObjectModel.ObservableCollection[object]
            foreach ($item in $FullCollection) {
                $isMatch = $false
                foreach ($prop in $item.PSObject.Properties) {
                    if ($prop.Value -is [string] -and $prop.Value.ToLower() -match $FilterText) {
                        $Filtered.Add($item)
                        $isMatch = $true
                        break
                    }
                }
            }
            $DataGrid.ItemsSource = $Filtered
        }
    }

    # GRÁFICA V3.6.5 (DÍA Y HORA)
    function Generate-Chart {
        param($timeGroups)
        if (-not $timeGroups -or $timeGroups.Count -eq 0) { $TimeChartImage.Source = $null; return }
        
        $maxPeticiones = ($timeGroups | Measure-Object Peticiones -Maximum).Maximum
        $groupCount = $timeGroups.Count
        $width = 600; $height = 300
        
        try {
            $bmp = New-Object System.Drawing.Bitmap $width, $height
            $graphics = [System.Drawing.Graphics]::FromImage($bmp)
            $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
            $graphics.Clear([System.Drawing.Color]::White)
            $barBrush = [System.Drawing.Brushes]::DodgerBlue
            $textBrush = [System.Drawing.Brushes]::Black
            $axisPen = [System.Drawing.Pen]::New([System.Drawing.Color]::Gray, 1)
            $font = New-Object System.Drawing.Font("Arial", 8)

            $graphics.DrawString("Frecuencia (Día y Hora) - Total: $groupCount", (New-Object System.Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Bold)), $textBrush, 10, 10)

            $leftMargin = 50; $bottomMargin = 40; $topMargin = 30; $rightMargin = 10
            $chartWidth = $width - $leftMargin - $rightMargin
            $chartHeight = $height - $topMargin - $bottomMargin
            
            $graphics.DrawLine($axisPen, $leftMargin, $topMargin + $chartHeight, $leftMargin, $topMargin)
            $graphics.DrawLine($axisPen, $leftMargin, $topMargin + $chartHeight, $leftMargin + $chartWidth, $topMargin + $chartHeight)

            $barWidth = if($groupCount -gt 0){ [int]($chartWidth / ($groupCount * 1.5)) } else { 0 } 
            $barSpacing = if($groupCount -gt 0){ $chartWidth / $groupCount } else { 0 }
            
            for ($i = 0; $i -lt $groupCount; $i++) {
                $group = $timeGroups[$i]
                $barHeight = [int]((($group.Peticiones / $maxPeticiones) * $chartHeight))
                $x = $leftMargin + ($i * $barSpacing) + ($barSpacing - $barWidth) / 2
                $y = $topMargin + $chartHeight - $barHeight
                $graphics.FillRectangle($barBrush, $x, $y, $barWidth, $barHeight)
                
                if($group.Peticiones -gt 0){ $graphics.DrawString($group.Peticiones, $font, $textBrush, $x, $y - 10) }
                
                $label = ($group.Hora -split " ")[1] 
                $graphics.TranslateTransform($x + $barWidth/2, $topMargin + $chartHeight + 5)
                $graphics.RotateTransform(90)
                $graphics.DrawString($label, $font, $textBrush, 0, 0)
                $graphics.ResetTransform()
            }
            $graphics.DrawString("Max: $maxPeticiones", $font, $textBrush, 5, $topMargin)

            $stream = New-Object System.IO.MemoryStream
            $bmp.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
            $bitmapImage = New-Object System.Windows.Media.Imaging.BitmapImage
            $bitmapImage.BeginInit(); $bitmapImage.StreamSource = $stream; $bitmapImage.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad; $bitmapImage.EndInit()
            
            $TimeChartImage.Source = $bitmapImage
            $graphics.Dispose(); $bmp.Dispose(); $stream.Dispose()
        } catch { $TimeChartImage.Source = $null }
    }

    function Populate-GridsFromTempData {
        $DataCollection.Clear(); $IpCollection.Clear(); $TimeCollection.Clear(); $UrlCollection.Clear(); $UACollection.Clear()
        $DataCollectionFull.Clear(); $IpCollectionFull.Clear(); $TimeCollectionFull.Clear(); $UrlCollectionFull.Clear(); $UACollectionFull.Clear()

        if($global:tempData){
            $global:tempData | ForEach-Object { $DataCollection.Add($_); $DataCollectionFull.Add($_) }
            
            $ipGroups = $global:tempData | Group-Object IP_Limpia | ForEach-Object { 
                $ip = $_.Name
                $saved = $global:CachedAnalysisData[$ip]
                $geo = Get-Geo $ip 
                $item = [PSCustomObject]@{
                    IP=$ip; Peticiones=$_.Count; Pais=$geo.Pais; Ciudad=$geo.Ciudad
                    AbuseScore=if($saved -and $saved.AbuseScore){$saved.AbuseScore}else{""}
                    AbuseSeveridad=if($saved -and $saved.AbuseSeveridad){$saved.AbuseSeveridad}else{""}
                    AbuseExplicacion=if($saved -and $saved.AbuseExplicacion){$saved.AbuseExplicacion}else{""}
                    FireHolCheck=if($saved -and $saved.FireHolCheck){$saved.FireHolCheck}else{""}
                    VT_Check=if($saved -and $saved.VT_Check){$saved.VT_Check}else{""}
                    VT_Explicacion=if($saved -and $saved.VT_Explicacion){$saved.VT_Explicacion}else{""}
                }
                $IpCollection.Add($item); $IpCollectionFull.Add($item)
            }
            # Agrupación Día y Hora (V3.6.5 Style)
            $timeGroups = $global:tempData | Group-Object { $_.Fecha_Hora.ToString("yyyy-MM-dd HH") } | Sort-Object Name 
            $timeGroups | ForEach-Object { $item=[PSCustomObject]@{Hora=$_.Name;Peticiones=$_.Count}; $TimeCollection.Add($item); $TimeCollectionFull.Add($item) }
            
            $global:tempData | Group-Object URL_Atacada | Sort-Object Count -Descending | ForEach-Object { $item=[PSCustomObject]@{URL=$_.Name;Peticiones=$_.Count}; $UrlCollection.Add($item); $UrlCollectionFull.Add($item) }
            $global:tempData | Group-Object UserAgent | Sort-Object Count -Descending | ForEach-Object { $item=[PSCustomObject]@{UserAgent=$_.Name;Peticiones=$_.Count}; $UACollection.Add($item); $UACollectionFull.Add($item) }
            
            Generate-Chart $TimeCollectionFull
        }
        Refresh-IpDataGrid
    }

    function Refresh-IpDataGrid {
        $IpGroupingDataGrid.ItemsSource = $null
        $IpGroupingDataGrid.ItemsSource = $IpCollection
        $CacheLabel.Text = "Cache: $($global:CachedAnalysisData.Count) IPs"
        
        # FIX ToArray (Loop manual)
        $tempList = @(); foreach ($item in $IpCollectionFull) { $tempList += $item }
        $IpCollectionFull.Clear(); $tempList | ForEach-Object { $IpCollectionFull.Add($_) }

        Apply-Filter $IpGroupingDataGrid $IpCollectionFull $Filter2.Text
    }

    function Invoke-SingleIPCheck {
        param($CheckType)
        $ipItem = $IpGroupingDataGrid.SelectedItem
        if(-not $ipItem -or -not $ipItem.IP){ [System.Windows.Forms.MessageBox]::Show("Seleccione una IP primero."); return }
        $ip = $ipItem.IP
        
        $StatusLabel.Text = "Consultando $CheckType para $ip..."; $ProcessingIndicator.Visibility = 'Visible'; [System.Windows.Forms.Application]::DoEvents()

        switch ($CheckType) {
            "GEO" { Get-Geo $ip }
            "Abuse" { Update-AbuseInfo $ip }
            "VT" { Update-VirusTotalInfo $ip }
            "FireHol" { Check-IpFireHol $ip }
        }
        
        # Refresco de la UI
        $updatedItem = $IpCollectionFull | Where-Object {$_.IP -eq $ip} | Select-Object -First 1
        if($updatedItem){
            $cache = $global:CachedAnalysisData[$ip]
            if($CheckType -eq "GEO"){ $updatedItem.Pais = $cache.Pais; $updatedItem.Ciudad = $cache.Ciudad }
            if($CheckType -eq "Abuse"){ $updatedItem.AbuseScore = $cache.AbuseScore; $updatedItem.AbuseSeveridad = $cache.AbuseSeveridad; $updatedItem.AbuseExplicacion = $cache.AbuseExplicacion }
            if($CheckType -eq "VT"){ $updatedItem.VT_Check = $cache.VT_Check; $updatedItem.VT_Explicacion = $cache.VT_Explicacion }
            if($CheckType -eq "FireHol"){ $updatedItem.FireHolCheck = $cache.FireHolCheck }
        }
        Refresh-IpDataGrid
        $ProcessingIndicator.Visibility = 'Collapsed'; $StatusLabel.Text = "$CheckType completado."
    }

    function Invoke-AllIPsCheck {
        param($CheckType)
        if($IpCollectionFull.Count -eq 0){ [System.Windows.Forms.MessageBox]::Show("Primero debe iniciar un análisis."); return }
        $StatusLabel.Text = "Iniciando $CheckType para todas las IPs..."; $ProcessingIndicator.Visibility = 'Visible'; [System.Windows.Forms.Application]::DoEvents()
        
        $i = 0
        foreach($item in $IpCollectionFull){
            $i++; $ip = $item.IP
            if($i % 5 -eq 0){ $StatusLabel.Text = "[$i/$($IpCollectionFull.Count)] $CheckType en $ip..."; [System.Windows.Forms.Application]::DoEvents() }

            switch ($CheckType) {
                "AbuseIPDB" { Update-AbuseInfo $ip }
                "VirusTotal" { Update-VirusTotalInfo $ip }
            }
            $cache = $global:CachedAnalysisData[$ip]
            if($CheckType -eq "AbuseIPDB"){ $item.AbuseScore = $cache.AbuseScore; $item.AbuseSeveridad = $cache.AbuseSeveridad; $item.AbuseExplicacion = $cache.AbuseExplicacion }
            if($CheckType -eq "VirusTotal"){ $item.VT_Check = $cache.VT_Check; $item.VT_Explicacion = $cache.VT_Explicacion }
        }
        Refresh-IpDataGrid; $ProcessingIndicator.Visibility = 'Collapsed'; $StatusLabel.Text = "$CheckType completado."
    }

    function Invoke-FireHolAll {
        if($IpCollectionFull.Count -eq 0){ [System.Windows.Forms.MessageBox]::Show("Inicie análisis primero."); return }
        if(-not $global:FireHolLoaded){ Load-FireHolRanges | Out-Null }

        $StatusLabel.Text = "Chequeando FireHol..."; $ProcessingIndicator.Visibility = 'Visible'; [System.Windows.Forms.Application]::DoEvents()
        foreach($item in $IpCollectionFull){
            Check-IpFireHol $item.IP | Out-Null
            $item.FireHolCheck = $global:CachedAnalysisData[$item.IP].FireHolCheck
        }
        Refresh-IpDataGrid; $ProcessingIndicator.Visibility = 'Collapsed'; $StatusLabel.Text = "FireHol Check completado."
    }

    # --- Handlers GUI ---
    $StartButton.Add_Click({
        $path = $LogPathTextBox.Text.Trim()
            # ========================================================================
        # FIX CRÍTICO: Validación de archivo (evita el error 'cadena vacía')
        # ========================================================================
    
        # 1. Verificar si el campo de texto está vacío o solo tiene espacios
        if ([string]::IsNullOrWhiteSpace($Path)) {
            [System.Windows.Forms.MessageBox]::Show(
                "ERROR: Debe seleccionar un archivo de log (.log) antes de iniciar el análisis.", 
                "Archivo Requerido", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Exclamation
            )
            return # Detiene la ejecución para no causar el error en consola
        }

        # 2. Verificar si la ruta existe (aunque esto se podría dejar en Invoke-LogParsing, 
        # es mejor gestionarlo aquí para mostrar el mensaje de la GUI)
        if (-not (Test-Path $Path -PathType Leaf)) {
            [System.Windows.Forms.MessageBox]::Show(
                "ERROR: La ruta especificada ('$Path') no existe o no es un archivo válido.", 
                "Archivo No Encontrado", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return # Detiene la ejecución
        }
        $ProcessingIndicator.Visibility='Visible'; $StatusLabel.Text="Iniciando análisis..."
        [System.Windows.Forms.Application]::DoEvents()
        
        $startTime = Get-Date
        $global:tempData = Invoke-LogParsing -Path $path -Level $RegexLevelComboBox.SelectedItem.Content
        $endTime = Get-Date
        $timeTaken = New-TimeSpan -Start $startTime -End $endTime
        
        Populate-GridsFromTempData
        
        $ProcessingIndicator.Visibility='Collapsed'; 
        $StatusLabel.Text="Completado en $($timeTaken.TotalSeconds.ToString("N2"))s. Líneas: $global:total | Matches: $global:matches"
        $CountLabel.Text="Resultados: $global:matches"
        [System.Windows.Forms.Application]::DoEvents()
    })

    $miIPGeo.Add_Click({ Invoke-SingleIPCheck "GEO" })
    $miIPAbuse.Add_Click({ Invoke-SingleIPCheck "Abuse" })
    $miIPVT.Add_Click({ Invoke-SingleIPCheck "VT" })
    $miIPFireHol.Add_Click({ Invoke-SingleIPCheck "FireHol" })

    $AbuseCheckButton.Add_Click({ Invoke-AllIPsCheck "AbuseIPDB" })
    $VirusTotalCheckButton.Add_Click({ Invoke-AllIPsCheck "VirusTotal" })
    $FireHolMenuButton.Add_Click({ $ctxFireHol.PlacementTarget = $FireHolMenuButton; $ctxFireHol.IsOpen = $true })

    $miFireHolLoad.Add_Click({ Load-FireHolRanges; Refresh-IpDataGrid })
    $miFireHolDownload.Add_Click({ 
        $StatusLabel.Text = "Descargando FireHol..."; $ProcessingIndicator.Visibility='Visible'; [System.Windows.Forms.Application]::DoEvents()
        try {
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset" -OutFile $global:FireHolFile -UseBasicParsing
            Load-FireHolRanges | Out-Null
            [System.Windows.Forms.MessageBox]::Show("FireHol descargado y cargado.", "Éxito")
        } catch { [System.Windows.Forms.MessageBox]::Show("Error descarga.") }
        $ProcessingIndicator.Visibility = 'Collapsed'
    })
    $miFH_All_Menu.Add_Click({ Invoke-FireHolAll })

    function Handle-CacheMenu {
        param($Action)
        switch ($Action) {
            "View" { [System.Windows.Forms.MessageBox]::Show(($global:CachedAnalysisData | ConvertTo-Json -Depth 5), "Cache") }
            "Save" {
                $sfd = New-Object System.Windows.Forms.SaveFileDialog; $sfd.Filter = "JSON|*.json"; $sfd.FileName = "Cache_Analysis_$(Get-Date -Format yyyyMMdd_HHmmss).json"
                if ($sfd.ShowDialog() -eq "OK") { Export-Cache-ToJson $global:tempData $global:CachedAnalysisData $global:CachedAI $sfd.FileName }
            }
            "Load" {
                $ofd = New-Object System.Windows.Forms.OpenFileDialog; $ofd.Filter = "JSON|*.json"
                if ($ofd.ShowDialog() -eq "OK") {
                    try {
                        $jsonContent = Get-Content $ofd.FileName -Raw -Encoding UTF8 | ConvertFrom-Json
                        
                        # FIX V4.6: Restaurar Contadores y Metadatos
                        if ($jsonContent.MetaData) {
                            $global:total = $jsonContent.MetaData.TotalLines
                            $global:matches = $jsonContent.MetaData.Matches
                        }

                        $global:tempData = New-Object System.Collections.Generic.List[object]
                        if ($jsonContent.Data) {
                            foreach($x in $jsonContent.Data){ 
                                if($x.Fecha_Hora -is [string]){ try{$x.Fecha_Hora=[datetime]$x.Fecha_Hora}catch{} }
                                $global:tempData.Add($x) 
                            }
                        }

                        # Restaurar la caché a un Hashtable de PowerShell 
                        $global:CachedAnalysisData = @{}
                        if($jsonContent.Enriched){
                            # Recorrer el PSCustomObject cargado para volver a Hashtable.
                            $jsonContent.Enriched.PSObject.Properties | ForEach-Object {
                                $ipKey = $_.Name
                                $innerObject = $_.Value
                                $innerHashtable = @{}
                                if ($innerObject) {
                                    $innerObject.PSObject.Properties | ForEach-Object {
                                        $innerHashtable[$_.Name] = $_.Value
                                    }
                                }
                                $global:CachedAnalysisData[$ipKey] = $innerHashtable
                            }
                        }
                        
                        if($jsonContent.AI){
                            $global:CachedAI.Prompt = $jsonContent.AI.Prompt
                            $global:CachedAI.Response = $jsonContent.AI.Response
                            $TxtPromptAI.Text = $jsonContent.AI.Prompt
                            $TxtResponseAI.Text = $jsonContent.AI.Response
                        }

                        Populate-GridsFromTempData
                        
                        $StatusLabel.Text = "Caché cargada: $($global:matches) matches de $($global:total) líneas."
                        $CountLabel.Text = "Resultados: $($global:matches)"

                    } catch { [System.Windows.Forms.MessageBox]::Show("Error al cargar: $($_.Exception.Message)", "Error") }
                }
            }
        }
    }
    $CacheMenuButton.Add_Click({ $ctxCache.PlacementTarget = $CacheMenuButton; $ctxCache.IsOpen = $true })
    $miCacheView.Add_Click({ Handle-CacheMenu "View" })
    $miCacheSave.Add_Click({ Handle-CacheMenu "Save" })
    $miCacheLoad.Add_Click({ Handle-CacheMenu "Load" })

    function Start-AI-Request {
        param($Mode)
        if($global:tempData.Count -eq 0){ [System.Windows.Forms.MessageBox]::Show("Primero inicie análisis."); return }
        $global:TargetApp = $AppInput.Text.Trim(); $global:TargetVersion = $VersionInput.Text.Trim()
        if ($Mode -eq "CVE" -and (-not $global:TargetApp -or -not $global:TargetVersion)) {
            [System.Windows.Forms.MessageBox]::Show("Modo CVE requiere Software y Versión."); return
        }

        $TabControl1.SelectedItem = $TabAI; [System.Windows.Forms.Application]::DoEvents()
        
        # GENERACIÓN DE PROMPT V3.6.5 (RESUMEN PREVIO + USER AGENTS + FECHA REAL)
        $topIPs = ($IpCollectionFull | Sort-Object Peticiones -Descending | Select-Object -First 5) | ForEach-Object { "IP: $($_.IP) | Req: $($_.Peticiones) | Geo: $($_.Pais) | Risk: Abuse:$($_.AbuseScore), VT:$($_.VT_Check)" }
        $topUrls = ($UrlCollectionFull | Select-Object -First 10).URL
        $topUAs = ($UserAgentGroupingDataGrid.ItemsSource | Select-Object -First 8) | ForEach-Object { "UA: $($_.UserAgent) | Req: $($_.Peticiones)" }
        
        # [FIX V4.4: Inyectar Fecha Actual]
        $currentDate = Get-Date -Format "yyyy-MM-dd"

        $prompt = "FECHA ACTUAL: $currentDate\n" +
                  "ROL: Analista de Seguridad. Analiza este log de Apache. \n" +
                  "RESUMEN:\nTotal Peticiones: $global:total\nMatches Sospechosos: $global:matches\n" +
                  "[Top 5 IPs Atacantes]\n" + ($topIPs -join "`n") + "\n" +
                  "[Top 10 URLs Atacadas]\n" + ($topUrls -join "`n") + "\n" +
                  "[Top User Agents]\n" + ($topUAs -join "`n")
        
        # --- ZONA EDITABLE: INSTRUCCIONES ADICIONALES ---
        # Aquí puedes añadir instrucciones extra para la IA si lo deseas.
        # Ejemplo: $prompt += "`nInstrucción extra: Ignora IPs de Google."
        
        if ($Mode -eq "CVE") {
            $StatusLabel.Text = "Consultando NVD..."; [System.Windows.Forms.Application]::DoEvents()
            $nvd = Get-NvdCveData
            
            # PODA EXACTA V3.6.5 (Con reconstrucción de objeto y scores)
            $PrunedCVEs = @()
            $severityMap = @{ "CRITICAL"=4; "HIGH"=3; "MEDIUM"=2; "LOW"=1; "NONE"=0; "N/A"=0 }

            if ($nvd -and $nvd.vulnerabilities) {
                $nvd.vulnerabilities | Sort-Object { 
                    $s = "N/A"; $m = $_.cve.metrics
                    if ($m.cvssMetricV31) { $s = $m.cvssMetricV31[0].cvssData.baseSeverity }
                    elseif ($m.cvssMetricV30) { $s = $m.cvssMetricV30[0].cvssData.baseSeverity }
                    elseif ($m.cvssMetricV2) { 
                        $sc = $m.cvssMetricV2[0].cvssData.baseScore
                        if($sc -ge 9.0){$s="CRITICAL"} elseif($sc -ge 7.0){$s="HIGH"} elseif($sc -ge 4.0){$s="MEDIUM"} else{$s="LOW"}
                    }
                    return $severityMap[$s]
                } -Descending | Select-Object -First 10 | ForEach-Object {
                    $cveItem = $_.cve; $m = $cveItem.metrics
                    $sev = "N/A"; $vec = "N/A"; $exp = "N/A"; $imp = "N/A"
                    
                    # Prioridad V3.1 > V3.0 > V2 (Lógica V3.6.5)
                    $metric = $null
                    if($m.cvssMetricV31){ 
                        $metric = $m.cvssMetricV31 | Where-Object {$_.source -match "nvd"} | Select-Object -First 1
                        if(-not $metric){$metric=$m.cvssMetricV31[0]}
                    }
                    elseif($m.cvssMetricV30){ 
                        $metric = $m.cvssMetricV30 | Where-Object {$_.source -match "nvd"} | Select-Object -First 1
                        if(-not $metric){$metric=$m.cvssMetricV30[0]}
                    }
                    elseif($m.cvssMetricV2){ $metric=$m.cvssMetricV2[0] }
                    
                    if ($metric) {
                        if($metric.cvssData.baseSeverity){ $sev=$metric.cvssData.baseSeverity; $vec=$metric.cvssData.attackVector }
                        elseif($metric.cvssData.baseScore){ $sev="V2 Score " + $metric.cvssData.baseScore; $vec=$metric.cvssData.accessVector }
                        
                        if ($metric.exploitabilityScore) { $exp=$metric.exploitabilityScore }
                        if ($metric.impactScore) { $imp=$metric.impactScore }
                    }
                    
                    $desc = $cveItem.descriptions[0].value
                    $PrunedCVEs += [PSCustomObject]@{ 
                        CVE_ID=$cveItem.id; 
                        Severidad=$sev; 
                        VectorAtaque=$vec; 
                        ExploitScore=$exp; 
                        ImpactScore=$imp; 
                        Descripcion=$desc 
                    }
                }
            }
            
            $prompt += "\n\nCONTEXTO CVE: App: $($global:TargetApp) v$($global:TargetVersion).\n" + 
                       "Vulnerabilidades (JSON Podado): " + ($PrunedCVEs | ConvertTo-Json -Depth 2 | Out-String)
        }
        
        $TxtPromptAI.Text = $prompt
        $StatusLabel.Text = "Consultando IA..."; $ProcessingIndicator.Visibility = 'Visible'; [System.Windows.Forms.Application]::DoEvents()

        $response = Invoke-AI-Provider -Prompt $prompt -ModelName $LLMSelector.SelectedItem.Content
        $global:CachedAI.Prompt = $prompt; $global:CachedAI.Response = $response
        $TxtResponseAI.Text = $response
        
        $ProcessingIndicator.Visibility = 'Collapsed'; $StatusLabel.Text = "Análisis IA Fin."
    }

    $BtnRequestAI.Add_Click({ Start-AI-Request "General" })
    $BtnRequestCVE.Add_Click({ Start-AI-Request "CVE" })

    $ClearButton.Add_Click({ 
        # FIX V4.6: Clear Button Freeze
        $StatusLabel.Text = "Limpiando..."
        [System.Windows.Forms.Application]::DoEvents()

        # Clear collections directly instead of unbinding
        $DataCollection.Clear(); $IpCollection.Clear(); $TimeCollection.Clear(); $UrlCollection.Clear(); $UACollection.Clear()
        $DataCollectionFull.Clear(); $IpCollectionFull.Clear(); $TimeCollectionFull.Clear(); $UrlCollectionFull.Clear(); $UACollectionFull.Clear()
        
        $global:tempData.Clear()
        $global:CachedAnalysisData = @{}
        $global:total = 0; $global:matches = 0
        
   # ========================================================================
    # 3. FIX: Limpieza de Elementos de ENTRADA (Faltante en el original)
    # ========================================================================
    
    # Limpia la ruta del log (CRÍTICO)
    $LogPathTextBox.Text = "" 
    
    # Limpia los campos de Target (Asumiendo que existen para el modo CVE)
    if ($TargetAppTextBox) { $TargetAppTextBox.Text = "" }
    if ($TargetVersionTextBox) { $TargetVersionTextBox.Text = "" }

    # Limpia los filtros dinámicos (CRÍTICO)
    $Filter1.Text = ""; 
    $Filter2.Text = ""; 
    $Filter3.Text = ""; 
    $Filter4.Text = "";
    $Filter5.Text = ""; 

    # ========================================================================
    # 4. Limpieza de Elementos de SALIDA y ESTADO
    # ========================================================================

    # Limpia las cajas de texto de IA
    $TxtPromptAI.Text = ""; 
    $TxtResponseAI.Text = ""
    # Asegúrate de limpiar también la respuesta CVE si tiene un control separado
    # if ($TxtResponseAI_CVE) { $TxtResponseAI_CVE.Text = "" }
    
    # Resetea las etiquetas de resumen
    $CountLabel.Text="Resultados: 0"
    $StatusLabel.Text="Datos borrados. Listo para un nuevo análisis." 
    
    # Limpia la fuente de la gráfica
    $TimeChartImage.Source = $null
    # Se recomienda añadir una función si hay más gráficas: Clear-AllCharts()

})

    $ExportMenuButton.Add_Click({ $ctxExport.PlacementTarget = $ExportMenuButton; $ctxExport.IsOpen = $true })
    $miExpExcel.Add_Click({ 
        $dg = Get-CurrentDataGrid; $col = @(Get-VisibleItems $dg) 
        if($col.Count -gt 0){ $sfd=New-Object System.Windows.Forms.SaveFileDialog; $sfd.Filter="Excel|*.xlsx"; $sfd.FileName = "LogAnalysis_Export_Excel_$(Get-Date -Format yyyyMMdd_HHmmss)"; 
            if($sfd.ShowDialog() -eq "OK"){ 
                $job = Export-Collection-ToExcel $col $sfd.FileName; 
                [System.Windows.Forms.MessageBox]::Show("Exportación iniciada.", "Info")
            } 
        }
    })
    $miExpCsv.Add_Click({ 
        $dg = Get-CurrentDataGrid; $col = @(Get-VisibleItems $dg) 
        if($col.Count -gt 0){ $sfd=New-Object System.Windows.Forms.SaveFileDialog; $sfd.Filter="CSV|*.csv"; $sfd.FileName = "LogAnalysis_Export_CSV_$(Get-Date -Format yyyyMMdd_HHmmss)"; if($sfd.ShowDialog() -eq "OK"){ Export-Collection-ToCsv $col $sfd.FileName; [System.Windows.Forms.MessageBox]::Show("Guardado.") } }
    })
    $miExpJson.Add_Click({ 
        $dg = Get-CurrentDataGrid; $col = @(Get-VisibleItems $dg) 
        if($col.Count -gt 0){ $sfd=New-Object System.Windows.Forms.SaveFileDialog; $sfd.Filter="JSON|*.json"; $sfd.FileName = "LogAnalysis_Export_JSON_$(Get-Date -Format yyyyMMdd_HHmmss)"; if($sfd.ShowDialog() -eq "OK"){ Export-Collection-ToJson $col $sfd.FileName; [System.Windows.Forms.MessageBox]::Show("Guardado.") } }
    })

    $BtnExportMarkdown.Add_Click({
        $md = $TxtResponseAI.Text; if([string]::IsNullOrWhiteSpace($md)){ return }
        $sfd=New-Object System.Windows.Forms.SaveFileDialog; $sfd.Filter="MD|*.md"; $sfd.FileName = "LogAnalysis_Report_IA_$(Get-Date -Format yyyyMMdd_HHmmss).md"
        if($sfd.ShowDialog() -eq "OK"){ Set-Content $sfd.FileName $md -Encoding UTF8; [System.Windows.Forms.MessageBox]::Show("Guardado.") }
    })

    $BrowseLogButton.Add_Click({ 
        $ofd = New-Object System.Windows.Forms.OpenFileDialog; $ofd.Filter = "Logs (*.log;*.txt)|*.log;*.txt|All (*.*)|*.*"
        if($ofd.ShowDialog() -eq "OK"){ $LogPathTextBox.Text = $ofd.FileName } 
    })

    $Filter1.Add_TextChanged({ Apply-Filter $ResultsDataGrid $DataCollectionFull $Filter1.Text })
    $Filter2.Add_TextChanged({ Apply-Filter $IpGroupingDataGrid $IpCollectionFull $Filter2.Text })
    $Filter3.Add_TextChanged({ Apply-Filter $TimeGroupingDataGrid $TimeCollectionFull $Filter3.Text })
    $Filter4.Add_TextChanged({ Apply-Filter $UrlGroupingDataGrid $UrlCollectionFull $Filter4.Text })
    $Filter5.Add_TextChanged({ Apply-Filter $UserAgentGroupingDataGrid $UACollectionFull $Filter5.Text })
    $ThemeSelector.Add_SelectionChanged({ Set-Theme $ThemeSelector.SelectedItem.Content })

    Set-Theme "Claro"
    Load-FireHolRanges | Out-Null 
    $window.ShowDialog() | Out-Null
}
