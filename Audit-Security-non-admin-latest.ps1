#requires -Version 5.1
<#
    Audit-Security-non-admin-latest.ps1
    Complemento da auditoria admin, para as duas verificacoes que normalmente
    ficam incompletas quando se olha so o perfil atual:

      A. ORIGEM DOS DOWNLOADS  (Zone.Identifier)
         Olhar so em C:\Users\*\Downloads costuma voltar vazio quando a pasta
         de downloads foi movida para outro drive. Este script descobre as
         pastas de download em TODOS os drives automaticamente.

      B. EXTENSOES DE NAVEGADOR DE TODOS OS PERFIS
         Varre todos os perfis de usuario que conseguir ler, nao apenas o seu.

    PROJETADO PARA RODAR SEM ADMIN.
    Nao precisa de elevacao e nao pede. Perfis de outros usuarios nao sao
    legiveis sem admin - o script detecta isso, segue em frente e lista no fim
    exatamente o que ficou de fora e por que. Rodando elevado, cobre tudo.

    SOMENTE LEITURA. Nao altera nada no sistema.

    O relatorio gerado contem dados sensiveis da maquina onde rodou
    (nomes de arquivos, perfis, extensoes). NAO publique o .txt.

    Uso:
        powershell -NoProfile -ExecutionPolicy Bypass -File .\Audit-Security-non-admin-latest.ps1

    Opcoes:
        -Dias 365                janela dos downloads (padrao: 180)
        -MaxArquivos 150         teto de arquivos listados por pasta (padrao: 80)
        -PastaExcluida 'F:\Save' pasta excluida do Defender que voce quer inspecionar
                                 (aceita varias, separadas por virgula; padrao: nenhuma)
        -SelfTest                so carrega o script e sai (teste de AMSI)

    Saida (gravada ao vivo, etapa a etapa):
        .\log\verifica-pendentes-latest.txt   + copia .\log\verifica-pendentes-<data>.txt
#>
param(
    [int]$Dias = 180,
    [int]$MaxArquivos = 80,
    [string[]]$PastaExcluida = @(),
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# --------------------------------------------------------------------------
# Se este script for iniciado a partir de um pwsh 7 (ou de qualquer shell que
# exporte o PSModulePath do 7), o PowerShell 5.1 acaba carregando os modulos do
# 7 e o Microsoft.PowerShell.Security falha com "member ... is already present",
# derrubando o Get-AuthenticodeSignature. Aqui tiramos os caminhos do 7 quando
# estamos rodando sob 5.1.
# --------------------------------------------------------------------------
if ($PSVersionTable.PSVersion.Major -le 5) {
    $limpo = ($env:PSModulePath -split ';' |
              Where-Object { $_ -and $_ -notmatch '(?i)\\powershell\\7|\\PowerShell\\Modules$' })
    if ($limpo) { $env:PSModulePath = ($limpo -join ';') }
    Import-Module Microsoft.PowerShell.Security -ErrorAction SilentlyContinue
}

# Assinatura com degradacao elegante: se o cmdlet nao estiver disponivel,
# devolve 'n/d' em vez de estourar e derrubar a etapa inteira.
$script:semAssinatura = $false
function Get-Assinatura {
    param([string]$Caminho)
    if (-not (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue)) {
        $script:semAssinatura = $true
        return [pscustomobject]@{ Estado = 'n/d'; Assinante = '(cmdlet indisponivel)' }
    }
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $Caminho -ErrorAction Stop
        # O CN nem sempre e o primeiro campo do Subject (ha certificados que
        # comecam com E=...), e pode vir entre aspas. Pega o CN onde ele estiver.
        $nome = ''
        if ($s.SignerCertificate) {
            $subj = $s.SignerCertificate.Subject
            $nome = $subj
            $m = [regex]::Match($subj, 'CN=(?:"(?<q>[^"]+)"|(?<p>[^,]+))')
            if ($m.Success) {
                $nome = if ($m.Groups['q'].Success) { $m.Groups['q'].Value } else { $m.Groups['p'].Value }
            }
            $nome = $nome.Trim()
            if ($nome.Length -gt 36) { $nome = $nome.Substring(0,33) + '...' }
        }
        return [pscustomobject]@{ Estado = [string]$s.Status; Assinante = $nome }
    } catch {
        return [pscustomobject]@{ Estado = 'erro'; Assinante = '' }
    }
}

$here  = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
# Todo relatorio vai para .\log\ - essa pasta esta no .gitignore, para que
# nenhum resultado desta maquina seja versionado por acidente.
$logDir = Join-Path $here 'log'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$live  = Join-Path $logDir 'verifica-pendentes-latest.txt'
$final = Join-Path $logDir "verifica-pendentes-$stamp.txt"

$script:sw        = $null
$script:erros     = 0
$script:semAcesso = New-Object System.Collections.Generic.List[string]
$script:t0        = Get-Date

# Nomes de funcao conferidos contra aliases nativos do PowerShell.
# (licao aprendida: 'H' e alias de Get-History e tem precedencia sobre funcoes)
function Open-Log {
    $script:sw = New-Object System.IO.StreamWriter($live, $false, (New-Object System.Text.UTF8Encoding $false))
    $script:sw.AutoFlush = $true
}
function Close-Log {
    if ($script:sw) { $script:sw.Flush(); $script:sw.Close(); $script:sw.Dispose(); $script:sw = $null }
}
function W {
    param($t)
    $s = [string]$t
    if ($script:sw) { $script:sw.WriteLine($s) }
    Write-Host $s
}
function Titulo {
    param([string]$t)
    W ''
    W ('=' * 78)
    W "## $t"
    W ('=' * 78)
}
function Passo {
    param([string]$Nome, [scriptblock]$Acao)
    W ''
    W "--- $Nome"
    $cron = [Diagnostics.Stopwatch]::StartNew()
    try {
        & $Acao
        $cron.Stop()
        W ("    [ok  {0:N1}s]" -f $cron.Elapsed.TotalSeconds)
    } catch {
        $cron.Stop()
        $script:erros++
        W "    [ERRO] $($_.Exception.Message)"
        W ("    [linha {0}]  [falhou apos {1:N1}s]" -f $_.InvocationInfo.ScriptLineNumber, $cron.Elapsed.TotalSeconds)
        W '    (as proximas etapas continuam normalmente)'
    }
}

if ($SelfTest) { Write-Host 'SELFTEST OK: carregou (passou pelo AMSI) e nao executou nada.' -ForegroundColor Green; exit 0 }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Open-Log
W "Verifica-Pendentes  -  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
W "Host: $env:COMPUTERNAME   Usuario: $env:USERDOMAIN\$env:USERNAME"
W "Elevado: $isAdmin   (nao e necessario - sem admin, perfis de outros usuarios ficam de fora)"
W "Janela dos downloads: $Dias dias   Teto por pasta: $MaxArquivos arquivos"
W 'Somente leitura. Gravacao incremental: este arquivo e atualizado a cada etapa.'

# =====================================================================
Titulo 'A. ORIGEM DOS DOWNLOADS (Zone.Identifier)'
# =====================================================================

$script:pastas = New-Object System.Collections.Generic.List[string]

Passo 'A1. Descobrir pastas de download em todos os drives' {
    $nomes  = 'Downloads','Download','Baixados','Save','Temp'
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name.Length -eq 1 }

    # raizes dos drives
    foreach ($d in $drives) {
        foreach ($n in $nomes) {
            $p = Join-Path "$($d.Name):\" $n
            if (Test-Path $p -ErrorAction SilentlyContinue) { [void]$script:pastas.Add($p) }
        }
    }
    # pasta Downloads de cada perfil de usuario.
    # -ErrorAction SilentlyContinue e necessario: sem admin, o proprio Test-Path
    # lanca UnauthorizedAccessException nos perfis de outros usuarios.
    foreach ($u in Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue) {
        $p = Join-Path $u.FullName 'Downloads'
        if (Test-Path $p -ErrorAction SilentlyContinue) {
            [void]$script:pastas.Add($p)
        } else {
            # distingue "nao existe" de "existe mas nao posso ler"
            try { [void][System.IO.Directory]::GetDirectories($u.FullName) }
            catch [System.UnauthorizedAccessException] { $script:semAcesso.Add("Downloads de $($u.Name)") }
            catch { }
        }
    }
    # pasta de download configurada no shell do usuario atual
    $reg = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -ErrorAction SilentlyContinue).'{374DE290-123F-4565-9164-39C4925E467B}'
    if ($reg) {
        $reg = [Environment]::ExpandEnvironmentVariables($reg)
        if ((Test-Path $reg) -and ($script:pastas -notcontains $reg)) { [void]$script:pastas.Add($reg) }
    }

    $script:pastas = [System.Collections.Generic.List[string]]@($script:pastas | Sort-Object -Unique)
    foreach ($p in $script:pastas) {
        $n = @(Get-ChildItem $p -File -Recurse -Depth 2 -Force -ErrorAction SilentlyContinue).Count
        $acesso = try { Get-ChildItem $p -ErrorAction Stop | Out-Null; 'ok' } catch { 'SEM ACESSO'; }
        if ($acesso -ne 'ok') { $script:semAcesso.Add("pasta $p") }
        W ("    {0,-45} arquivos={1,-6} acesso={2}" -f $p, $n, $acesso)
    }
    if ($script:pastas.Count -eq 0) { W '    Nenhuma pasta de download encontrada.' }
}

Passo "A2. Origem dos arquivos baixados (ultimos $Dias dias)" {
    $corte = (Get-Date).AddDays(-$Dias)
    $achou = $false
    foreach ($p in $script:pastas) {
        $arqs = @(Get-ChildItem $p -File -Recurse -Depth 2 -Force -ErrorAction SilentlyContinue |
                  Where-Object { $_.LastWriteTime -gt $corte } |
                  Sort-Object LastWriteTime -Descending | Select-Object -First $MaxArquivos)
        if ($arqs.Count -eq 0) { continue }
        W ''
        W "    === $p  ($($arqs.Count) arquivos na janela) ==="
        foreach ($a in $arqs) {
            $z = Get-Content "$($a.FullName):Zone.Identifier" -ErrorAction SilentlyContinue
            if (-not $z) { continue }
            $achou = $true
            $zone = (($z | Where-Object { $_ -match '^ZoneId=' }) -replace 'ZoneId=','')
            $url  = (($z | Where-Object { $_ -match '^(HostUrl|ReferrerUrl)=' }) -replace '^(HostUrl|ReferrerUrl)=','' |
                     Select-Object -Unique) -join '  <- '
            W ("    {0:yyyy-MM-dd HH:mm}  zona={1}  {2}" -f $a.LastWriteTime, $zone, $a.Name)
            if ($url) { W "         origem: $url" }
        }
    }
    if (-not $achou) {
        W ''
        W '    Nenhum arquivo com Zone.Identifier na janela.'
        W '    (O marcador some quando o arquivo e desbloqueado, movido entre volumes,'
        W '     extraido de um zip ja desbloqueado, ou gravado em volume nao-NTFS.)'
    }
}

Passo 'A3. Executaveis nas pastas de download, com assinatura' {
    $ext = '.exe','.msi','.dll','.scr','.bat','.cmd','.ps1','.vbs','.js','.jar','.hta','.msix','.appx'
    $lin = 0
    foreach ($p in $script:pastas) {
        $arqs = @(Get-ChildItem $p -File -Recurse -Depth 2 -Force -ErrorAction SilentlyContinue |
                  Where-Object { $ext -contains $_.Extension.ToLower() } |
                  Sort-Object LastWriteTime -Descending | Select-Object -First $MaxArquivos)
        if ($arqs.Count -eq 0) { continue }
        W ''
        W "    === $p ==="
        foreach ($a in $arqs) {
            $sig = Get-Assinatura $a.FullName
            $marca = if ($sig.Estado -notin 'Valid','n/d') { '  <<< NAO ASSINADO / INVALIDO' } else { '' }
            W ("    {0:yyyy-MM-dd}  {1,8} KB  {2,-14} {3,-38} {4}{5}" -f $a.LastWriteTime, [int]($a.Length/1KB), $sig.Estado, $sig.Assinante, $a.Name, $marca)
            $lin++
        }
    }
    if ($lin -eq 0) { W '    Nenhum executavel encontrado nas pastas de download.' }
}

# Pastas que o usuario informou estarem na lista de exclusoes do Defender.
# Nada e escaneado dentro delas, entao vale listar o que ha de executavel.
# Passe com -PastaExcluida 'F:\Save','D:\Tools'. Sem o parametro, o passo e pulado.
if ($PastaExcluida.Count -gt 0) {
    Passo 'A4. Pastas excluidas do Defender - conteudo executavel' {
        $ext = '.exe','.msi','.dll','.scr','.bat','.cmd','.ps1','.vbs','.js','.jar','.hta'
        foreach ($p in $PastaExcluida) {
            W ''
            W "    === $p ==="
            if (-not (Test-Path $p)) { W "    $p nao existe."; continue }
            $todos = @(Get-ChildItem $p -File -Recurse -Force -ErrorAction SilentlyContinue)
            $arqs  = @($todos | Where-Object { $ext -contains $_.Extension.ToLower() })
            W "    Total de arquivos na pasta: $($todos.Count)"
            W "    Executaveis/scripts: $($arqs.Count)"
            foreach ($a in ($arqs | Sort-Object LastWriteTime -Descending | Select-Object -First $MaxArquivos)) {
                $sig = Get-Assinatura $a.FullName
                W ("    {0:yyyy-MM-dd}  {1,8} KB  {2,-14} {3,-30} {4}" -f $a.LastWriteTime, [int]($a.Length/1KB), $sig.Estado, $sig.Assinante, $a.FullName)
            }
        }
    }
}

# =====================================================================
Titulo 'B. EXTENSOES DE NAVEGADOR - TODOS OS PERFIS ACESSIVEIS'
# =====================================================================

Passo 'B1. Extensoes instaladas, por usuario e por perfil do navegador' {
    # Permissoes que dao alcance amplo sobre o que voce ve e digita na web.
    $amplas = 'nativeMessaging','debugger','<all_urls>','webRequest','webRequestBlocking',
              'proxy','privacy','cookies','clipboardRead','management','declarativeNetRequest',
              'http://*/*','https://*/*','*://*/*'

    $bases = @(
        @{ Nav='Chrome'; Rel='AppData\Local\Google\Chrome\User Data' },
        @{ Nav='Edge';   Rel='AppData\Local\Microsoft\Edge\User Data' },
        @{ Nav='Brave';  Rel='AppData\Local\BraveSoftware\Brave-Browser\User Data' },
        @{ Nav='Opera';  Rel='AppData\Roaming\Opera Software\Opera Stable' },
        @{ Nav='Vivaldi';Rel='AppData\Local\Vivaldi\User Data' }
    )

    $total = 0; $comRisco = 0
    foreach ($u in Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue) {
        if ($u.Name -in 'All Users','Default','Default User','Public') { continue }

        # consegue ler este perfil?
        $teste = $null
        try { $teste = Get-ChildItem $u.FullName -Force -ErrorAction Stop } catch { }
        if (-not $teste) {
            W ""
            W "    ### usuario $($u.Name): SEM ACESSO (precisa de elevacao)"
            $script:semAcesso.Add("perfil de usuario $($u.Name)")
            continue
        }

        $achouAlgo = $false
        foreach ($b in $bases) {
            $raiz = Join-Path $u.FullName $b.Rel
            if (-not (Test-Path $raiz)) { continue }
            foreach ($prof in @(Get-ChildItem $raiz -Directory -ErrorAction SilentlyContinue)) {
                $dirExt = Join-Path $prof.FullName 'Extensions'
                if (-not (Test-Path $dirExt)) { continue }
                foreach ($e in @(Get-ChildItem $dirExt -Directory -ErrorAction SilentlyContinue)) {
                    $ver = @(Get-ChildItem $e.FullName -Directory -ErrorAction SilentlyContinue | Sort-Object Name) |
                           Select-Object -Last 1
                    if (-not $ver) { continue }          # <- o bug que derrubou a etapa na auditoria
                    $mj = Join-Path $ver.FullName 'manifest.json'
                    if (-not (Test-Path $mj)) { continue }
                    $j = $null
                    try { $j = Get-Content $mj -Raw -ErrorAction Stop | ConvertFrom-Json } catch { continue }

                    $nome = [string]$j.name
                    if ($nome -like '__MSG_*') {
                        $chave = $nome -replace '^__MSG_|__$',''
                        foreach ($loc in 'en','en_US','pt_BR','_default') {
                            $lf = Join-Path $ver.FullName "_locales\$loc\messages.json"
                            if (Test-Path $lf) {
                                try { $m = Get-Content $lf -Raw | ConvertFrom-Json; if ($m.$chave.message) { $nome = $m.$chave.message; break } } catch { }
                            }
                        }
                    }
                    if (-not $nome) { $nome = '(sem nome no manifest)' }

                    $perms = @($j.permissions) + @($j.host_permissions) + @($j.optional_permissions) |
                             Where-Object { $_ -is [string] }
                    $bate = @($perms | Where-Object { $amplas -contains $_ })
                    $marca = ''
                    if ($bate.Count -gt 0) { $marca = "   <<< AMPLA: $($bate -join ',')"; $comRisco++ }

                    if (-not $achouAlgo) { W ''; W "    ### usuario $($u.Name)"; $achouAlgo = $true }
                    W ("    [{0}/{1}] {2}{3}" -f $b.Nav, $prof.Name, $nome, $marca)
                    W ("         id={0}  v={1}" -f $e.Name, $ver.Name)
                    if ($perms) { W ("         perms: {0}" -f ($perms -join ',')) }
                    $total++
                }
            }
        }
        if ($teste -and -not $achouAlgo) { W ''; W "    ### usuario $($u.Name): nenhuma extensao encontrada" }
    }
    W ''
    W "    TOTAL: $total extensoes, $comRisco com permissao ampla."
    W '    NOTA: permissao ampla nao significa maliciosa. Gerenciadores de senha e'
    W '    plugins de certificado digital precisam desse escopo. O que importa e'
    W '    reconhecer o editor de cada uma.'
}

Passo 'B2. Extensoes forcadas por politica (vetor classico de malware)' {
    $achou = $false
    foreach ($k in 'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist',
                   'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist',
                   'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallForcelist',
                   'HKCU:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist',
                   'HKCU:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist') {
        if (Test-Path $k) {
            $it = Get-Item $k
            foreach ($p in $it.Property) { $achou = $true; W "    $k :: $p = $((Get-ItemProperty $k).$p)" }
        }
    }
    if (-not $achou) { W '    Nenhuma extensao forcada por politica. (bom)' }
}

Passo 'B3. Extensoes instaladas fora da loja (external_extensions)' {
    $achou = $false
    foreach ($k in 'HKLM:\SOFTWARE\Google\Chrome\Extensions','HKLM:\SOFTWARE\Wow6432Node\Google\Chrome\Extensions',
                   'HKLM:\SOFTWARE\Microsoft\Edge\Extensions','HKCU:\SOFTWARE\Google\Chrome\Extensions') {
        if (Test-Path $k) {
            foreach ($s in Get-ChildItem $k -ErrorAction SilentlyContinue) {
                $v = Get-ItemProperty $s.PSPath
                $achou = $true
                W "    $($s.PSChildName)  path=$($v.path)  url=$($v.update_url)"
            }
        }
    }
    if (-not $achou) { W '    Nenhuma extensao registrada via registro fora da loja.' }
}

# =====================================================================
Titulo 'RESUMO'
# =====================================================================

W ''
W "Etapas com erro: $($script:erros)"
W ''
if ($script:semAcesso.Count -gt 0) {
    W 'O QUE FICOU DE FORA POR FALTA DE PERMISSAO:'
    foreach ($x in ($script:semAcesso | Sort-Object -Unique)) { W "   - $x" }
    W ''
    if (-not $isAdmin) {
        W 'Para cobrir esses itens, rode o mesmo script num PowerShell ELEVADO.'
        W 'Nada mais muda: o restante do resultado e identico.'
    }
} else {
    W 'Nada ficou de fora por permissao.'
}
W ''
W ("Duracao: {0:N1}s" -f ((Get-Date) - $script:t0).TotalSeconds)
W "Arquivo: $live"

Close-Log
Copy-Item $live $final -Force
Write-Host ''
Write-Host "Relatorio salvo em:" -ForegroundColor Green
Write-Host "   $live"
Write-Host "   $final"
Write-Host 'Somente leitura - nada foi alterado no sistema.' -ForegroundColor Cyan
