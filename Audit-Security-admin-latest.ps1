#requires -Version 5.1
<#
    Audit-Security-admin-latest.ps1
    Coleta SOMENTE LEITURA de estado de seguranca do Windows 11.
    Nao altera nada no sistema. Precisa ser executado ELEVADO.

    O relatorio gerado contem dados sensiveis da maquina onde rodou
    (contas, hashes de politica, caminhos, eventos). NAO publique o .txt.

    NOVO NA v1.2
      - Corrigido o travamento na etapa do agente de RMM (registro com -Recurse).
      - Saida agora e audit-v12[-sN]-latest.txt: NUNCA sobrescreve o relatorio
        anterior, e com -OnlySection o nome leva as secoes no sufixo.
      - Com -OnlySection, as secoes puladas nao poluem mais o arquivo.
      - Query 4104 reduzida de 30d/3000 para 7d/1500 eventos.

    NOVO NA v1.1
      - Grava o relatorio INCREMENTALMENTE (flush por etapa). Se for interrompido
        com Ctrl+C ou morrer no meio, tudo que ja rodou esta no arquivo.
      - Mostra progresso no console: etapa atual, tempo de cada uma.
      - Grava tempo de execucao por etapa no relatorio (ajuda a achar gargalo).
      - -SkipSlow pula as 4 etapas pesadas (DISM e varreduras de assinatura).
      - -OnlySection N  roda apenas a secao N (1..10).

    Uso (PowerShell como Administrador, nesta pasta):
        powershell -NoProfile -ExecutionPolicy Bypass -File .\Audit-Security-admin-latest.ps1

    Versao rapida (sem DISM nem varredura de assinaturas em disco):
        ... -File .\Audit-Security-admin-latest.ps1 -SkipSlow

    Investigacao dirigida (opcional, tudo desligado por padrao):
        -SuspectAccount 'ADMIN_exemplo'   detalha essa conta local e o perfil dela
        -RmmVendor 'action1'              detalha o agente de RMM/gestao com esse nome
        -IncidentDate '2026-09-30'        janela de +-2 dias usada nas buscas acima

    Saida (gravada ao vivo): .\log\audit-latest.txt
                             (com -OnlySection 9,10 -> .\log\audit-s9_10-latest.txt)
    Copia arquivada no fim:  .\log\audit[-sN]-<data>.txt
#>
param(
    [switch]$SelfTest,
    [switch]$SkipSlow,
    [string]$OnlySection,
    [string]$SuspectAccount,
    [string]$RmmVendor,
    [string]$IncidentDate
)

# v1.2b: o cmd.exe trata virgula como separador de argumento, entao '-OnlySection 9,10'
# chegava aqui como '910'. Agora aceitamos texto livre e extraimos os numeros:
#   -OnlySection 9,10   -OnlySection "9,10"   -OnlySection 9 10   -OnlySection 9;10
$SecoesAlvo = @()
 if ($OnlySection) { $SecoesAlvo = @($OnlySection -split '[^0-9]+' | Where-Object { $_ } | ForEach-Object { [int]$_ }) }

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$sufixo = if ($SecoesAlvo) { '-s' + ($SecoesAlvo -join '_') } else { '' }

# Todo relatorio vai para .\log\ - essa pasta esta no .gitignore, para que
# nenhum resultado desta maquina seja versionado por acidente.
$logDir = Join-Path $here 'log'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$live   = Join-Path $logDir "audit$sufixo-latest.txt"
$final  = Join-Path $logDir "audit$sufixo-$stamp.txt"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ------------------------------------------------- gravacao incremental
$script:sw      = $null
$script:secAtual = 0
$script:t0      = Get-Date

function Open-Log {
    $script:sw = New-Object System.IO.StreamWriter($live, $false, (New-Object System.Text.UTF8Encoding $false))
    $script:sw.AutoFlush = $true   # <- cada linha vai pro disco na hora
}
function Close-Log {
    if ($script:sw) { $script:sw.Flush(); $script:sw.Close(); $script:sw.Dispose(); $script:sw = $null }
}

function W { param($t) if ($script:sw) { $script:sw.WriteLine([string]$t) } }

# v1.2c: a funcao se chamava 'H', que e ALIAS NATIVO de Get-History no PowerShell.
# Alias tem precedencia sobre funcao, entao 'H 9 ...' chamava Get-History -Count 9,
# a funcao nunca rodava, $script:secAtual ficava 0 e -OnlySection pulava tudo.
function NovaSecao {
    param([int]$N, [string]$t)
    $script:secAtual = $N
    if ($SecoesAlvo -and $N -notin $SecoesAlvo) { return }
    W ''
    W ('=' * 78)
    W ("## $N. $t")
    W ('=' * 78)
    Write-Host ''
    Write-Host ("== SECAO $N : $t") -ForegroundColor Cyan
}

function Run {
    param([string]$Label, [scriptblock]$Block, [switch]$Slow)

    if ($SecoesAlvo -and $script:secAtual -notin $SecoesAlvo) { return }

    if ($Slow -and $SkipSlow) {
        W ''
        W "-- $Label"
        W '   [PULADO por -SkipSlow]'
        Write-Host ("   . $Label  (pulado)") -ForegroundColor DarkGray
        return
    }

    Write-Host ("   > $Label") -NoNewline
    $sw2 = [Diagnostics.Stopwatch]::StartNew()
    W ''
    W "-- $Label"
    try {
        $r = & $Block
        if ($null -eq $r -or ($r -is [array] -and $r.Count -eq 0)) {
            W '   (vazio / nenhum resultado)'
        } else {
            ($r | Out-String -Width 200).TrimEnd() -split "`r?`n" | ForEach-Object { W $_ }
        }
    } catch {
        W "   [ERRO] $($_.Exception.Message)"
    }
    $sw2.Stop()
    W ("   [tempo: {0:N1}s]" -f $sw2.Elapsed.TotalSeconds)
    Write-Host ("   {0,8:N1}s" -f $sw2.Elapsed.TotalSeconds) -ForegroundColor DarkGray
}

# ------------------------------------------------------------------ inicio
Open-Log

W "Audit-Security-Admin v1.2  -  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
W "Host: $env:COMPUTERNAME   Usuario: $env:USERDOMAIN\$env:USERNAME   Elevado: $isAdmin"
W "PSVersion: $($PSVersionTable.PSVersion)   SkipSlow: $SkipSlow   Secoes: $(if($SecoesAlvo){$SecoesAlvo -join ','}else{'todas'})"
W 'Gravacao incremental: este arquivo e atualizado a cada etapa.'

if ($SelfTest) {
    W 'SELFTEST'
    Close-Log
    Write-Host 'SELFTEST OK: carregou (passou pelo AMSI) e nao executou a coleta.' -ForegroundColor Green
    exit 0
}
if (-not $isAdmin) {
    W ''
    W '!!! NAO esta elevado. Varias secoes vao sair vazias.'
    Write-Host 'AVISO: nao esta elevado - muitas secoes vao sair vazias.' -ForegroundColor Yellow
}

Write-Host ''
Write-Host "Gravando ao vivo em: $live" -ForegroundColor Green
Write-Host 'Pode interromper com Ctrl+C a qualquer momento - o que ja rodou fica salvo.' -ForegroundColor Green

# ---------------------------------------------------------------- 1. CONTAS
NovaSecao 1 'CONTAS, GRUPOS E CONTAS OCULTAS'

Run 'net user (lista crua do SAM)' { net user }
Run 'net localgroup Administrators' { net localgroup Administrators }
Run 'Get-LocalUser' { Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,PasswordLastSet,PasswordExpires,LastLogon,UserMayChangePassword,Description | Format-Table -AutoSize }
Run 'Chaves do SAM (nomes de conta no registro)' {
    Get-ChildItem 'HKLM:\SAM\SAM\Domains\Account\Users\Names' | Select-Object -ExpandProperty PSChildName
}
Run 'RIDs presentes no SAM' {
    Get-ChildItem 'HKLM:\SAM\SAM\Domains\Account\Users' |
        Where-Object PSChildName -match '^[0-9A-F]{8}$' |
        ForEach-Object { [Convert]::ToInt32($_.PSChildName,16) } | Sort-Object
}
Run 'reg query do SAM (fallback se o provider falhar)' {
    reg query 'HKLM\SAM\SAM\Domains\Account\Users\Names' 2>&1
}
if ($SuspectAccount) {
    Run "net user $SuspectAccount  <<< CONTA EM INVESTIGACAO" { net user $SuspectAccount }
}
Run 'Detalhe WMI de cada conta' {
    Get-CimInstance Win32_UserAccount | Select-Object Name,SID,Disabled,PasswordRequired,PasswordChangeable,PasswordExpires,AccountType,Status | Format-Table -AutoSize
}
if ($SuspectAccount) {
    $perfilAlvo = Join-Path $env:SystemDrive "Users\$SuspectAccount"
    Run "Perfil $perfilAlvo (raiz)" {
        Get-ChildItem $perfilAlvo -Force | Select-Object Mode,LastWriteTime,Length,Name | Format-Table -AutoSize
    }
    Run "Arquivos recentes no perfil $SuspectAccount (top 40)" {
        Get-ChildItem $perfilAlvo -Recurse -Force -File |
            Sort-Object LastWriteTime -Descending | Select-Object -First 40 LastWriteTime,Length,FullName |
            Format-Table -AutoSize
    }
}
Run 'Politica de senha / lockout (net accounts)' { net accounts }
Run 'Direitos sensiveis (secedit export)' {
    $tmp = Join-Path $env:TEMP "sec-$stamp.inf"
    secedit /export /cfg $tmp /quiet | Out-Null
    Get-Content $tmp | Where-Object { $_ -match '^(MinimumPasswordLength|PasswordComplexity|LockoutBadCount|MaximumPasswordAge|SeDenyNetworkLogonRight|SeDenyRemoteInteractiveLogonRight|SeNetworkLogonRight|SeRemoteInteractiveLogonRight|SeDebugPrivilege|SeBackupPrivilege|SeImpersonatePrivilege|SeTcbPrivilege|SeServiceLogonRight|EnableAdminAccount|EnableGuestAccount|NewAdministratorName|LSAAnonymousNameLookup|ForceLogoffWhenHourExpire)' }
    Remove-Item $tmp -Force
}

# ------------------------------------------------- 2. EVENTOS DE SEGURANCA
NovaSecao 2 'LOG DE SEGURANCA (contas criadas, privilegios, logons)'

Run '4720 - contas criadas  <<< QUEM CRIOU CADA CONTA LOCAL' {
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720} -MaxEvents 30 |
        ForEach-Object { '{0}  conta={1}  por={2}\{3}' -f $_.TimeCreated, $_.Properties[0].Value, $_.Properties[5].Value, $_.Properties[4].Value }
}
Run '4732 - membro adicionado a grupo local  <<< QUEM DEU ADMIN' {
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4732} -MaxEvents 40 |
        ForEach-Object { '{0}  grupo={1}  membro={2}  por={3}' -f $_.TimeCreated, $_.Properties[2].Value, $_.Properties[1].Value, $_.Properties[6].Value }
}
Run '4722/4724/4738 - habilitada / senha resetada / alterada' {
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4722,4724,4738} -MaxEvents 40 |
        ForEach-Object { '{0}  id={1}  alvo={2}  por={3}' -f $_.TimeCreated, $_.Id, $_.Properties[0].Value, $_.Properties[4].Value }
}
Run '4726/4733 - conta apagada / membro removido' {
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4726,4733} -MaxEvents 30 |
        ForEach-Object { '{0}  id={1}  {2}' -f $_.TimeCreated, $_.Id, ($_.Properties[0].Value) }
}
Run '1102 - log de seguranca limpo (apagamento de rastro)' {
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 10 | Select-Object TimeCreated,Message
}
Run '4625 - falhas de logon, 14 dias (resumo)' -Slow {
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddDays(-14)} -MaxEvents 1500 |
        ForEach-Object { [pscustomobject]@{ Conta=$_.Properties[5].Value; Origem=$_.Properties[19].Value; Tipo=$_.Properties[10].Value } } |
        Group-Object Conta,Origem,Tipo | Sort-Object Count -Descending | Select-Object -First 30 Count,Name
}
Run '4624 - logons de rede/RDP (tipo 3 e 10), 14 dias' -Slow {
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=(Get-Date).AddDays(-14)} -MaxEvents 2500 |
        Where-Object { $_.Properties[8].Value -in 3,10 } |
        ForEach-Object { [pscustomobject]@{ Conta=$_.Properties[5].Value; Tipo=$_.Properties[8].Value; Origem=$_.Properties[18].Value } } |
        Group-Object Conta,Tipo,Origem | Sort-Object Count -Descending | Select-Object -First 40 Count,Name
}
Run '4672 - logon com privilegio especial (quem usou admin), 14 dias' -Slow {
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4672;StartTime=(Get-Date).AddDays(-14)} -MaxEvents 1500 |
        ForEach-Object { $_.Properties[1].Value } | Group-Object | Sort-Object Count -Descending | Select-Object Count,Name
}
Run 'Politica de auditoria efetiva' { auditpol /get /category:* }
Run 'Retencao do log de Seguranca' {
    Get-WinEvent -ListLog Security | Select-Object LogName,MaximumSizeInBytes,RecordCount,LogMode,IsEnabled | Format-List
}

# ------------------------------------------------------------- 3. DEFENDER
NovaSecao 3 'MICROSOFT DEFENDER (exclusoes, ASR, ameacas)'

Run 'EXCLUSOES  <<< PONTO CEGO DE AV, O MAIS IMPORTANTE' {
    $p = Get-MpPreference
    [pscustomobject]@{
        ExclusionPath      = ($p.ExclusionPath      -join ' ; ')
        ExclusionExtension = ($p.ExclusionExtension -join ' ; ')
        ExclusionProcess   = ($p.ExclusionProcess   -join ' ; ')
        ExclusionIpAddress = ($p.ExclusionIpAddress -join ' ; ')
    } | Format-List
}
Run 'Exclusoes via registro' {
    'Paths','Extensions','Processes','IpAddresses' | ForEach-Object {
        $k = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\$_"
        $v = (Get-Item $k).Property
        $txt = if ($v) { $v -join ' ; ' } else { '(nenhuma)' }
        "[$_] $txt"
    }
}
Run 'Exclusoes/config por politica' {
    Get-ChildItem 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Recurse |
        ForEach-Object { $k=$_; $k.Property | ForEach-Object { "$($k.PSPath -replace '.*Policies\\','') :: $_ = $((Get-ItemProperty $k.PSPath).$_)" } }
}
Run 'Status completo' { Get-MpComputerStatus | Format-List }
Run 'Preferencias completas' { Get-MpPreference | Format-List }
Run 'Regras ASR (id -> acao)  0=Off 1=Block 2=Audit 6=Warn' {
    $p = Get-MpPreference
    for ($i=0; $i -lt $p.AttackSurfaceReductionRules_Ids.Count; $i++) {
        '{0}  =>  {1}' -f $p.AttackSurfaceReductionRules_Ids[$i], $p.AttackSurfaceReductionRules_Actions[$i]
    }
}
Run 'Ameacas detectadas (historico)' { Get-MpThreat | Select-Object ThreatName,SeverityID,IsActive,DidThreatExecute,Resources,RollupStatus | Format-List }
Run 'Deteccoes individuais' { Get-MpThreatDetection | Select-Object InitialDetectionTime,LastThreatStatusChangeTime,ThreatID,ThreatStatusID,ActionSuccess,ProcessName,Resources | Format-List }
Run 'Eventos Defender relevantes (deteccao, config, tamper)' {
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';Id=1006,1007,1008,1015,1116,1117,1118,1119,1121,1127,5001,5004,5007,5010,5012} -MaxEvents 80 |
        Select-Object TimeCreated,Id,@{n='Msg';e={($_.Message -split "`r?`n" | Where-Object {$_ -match '\S'})[0..3] -join ' | '}} | Format-Table -Wrap
}
Run 'AV/Firewall de terceiros registrados no Security Center' {
    Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState,pathToSignedProductExe,timestamp | Format-List
    Get-CimInstance -Namespace root\SecurityCenter2 -ClassName FirewallProduct | Select-Object displayName,productState | Format-List
}

# --------------------------------------------------------- 4. BOOT / DISCO
NovaSecao 4 'BOOT, TPM, BITLOCKER, VBS'

Run 'Secure Boot' { "Confirm-SecureBootUEFI = $(Confirm-SecureBootUEFI)" }
Run 'Sistema / hypervisor' { Get-CimInstance Win32_ComputerSystem | Select-Object BootupState,Manufacturer,Model,SystemType,HypervisorPresent,PCSystemType | Format-List }
Run 'TPM' { Get-Tpm | Format-List }
Run 'BitLocker - volumes' { Get-BitLockerVolume | Select-Object MountPoint,VolumeType,VolumeStatus,ProtectionStatus,LockStatus,EncryptionPercentage,EncryptionMethod,AutoUnlockEnabled | Format-Table -AutoSize }
Run 'BitLocker - protetores de chave' {
    Get-BitLockerVolume | ForEach-Object {
        $v=$_; "[$($v.MountPoint)]"
        $v.KeyProtector | ForEach-Object { "    $($_.KeyProtectorType)  id=$($_.KeyProtectorId)" }
    }
}
Run 'Device Guard / VBS / HVCI' {
    Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
        Select-Object AvailableSecurityProperties,SecurityServicesConfigured,SecurityServicesRunning,RequiredSecurityProperties,VirtualizationBasedSecurityStatus,CodeIntegrityPolicyEnforcementStatus,UsermodeCodeIntegrityPolicyEnforcementStatus | Format-List
}
Run 'bcdedit (testsigning, debug, nointegritychecks)' { bcdedit /enum '{current}' }
Run 'Cenarios DeviceGuard no registro' {
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' | Format-List Enabled,WasEnabledBy
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard' | Format-List Enabled
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\LocalSecurityAuthority' | Format-List Enabled
}
Run 'LSASS protegido e Credential Guard' {
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' | Format-List RunAsPPL,RunAsPPLBoot,LsaCfgFlags,DisableRestrictedAdmin
}
Run 'Blocklist de drivers vulneraveis' {
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' | Format-List VulnerableDriverBlocklistEnable
}

# -------------------------------------------------------- 5. PERSISTENCIA
NovaSecao 5 'PERSISTENCIA E CARREGAMENTO DE CODIGO'

Run 'AppInit_DLLs / AppCertDlls (injecao global)' {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' | Format-List AppInit_DLLs,LoadAppInit_DLLs,RequireSignedAppInit_DLLs
    Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows' | Format-List AppInit_DLLs,LoadAppInit_DLLs
    'AppCertDlls:'; (Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls').Property
}
Run 'Winlogon (Shell, Userinit, Notify, GinaDLL)' {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' | Format-List Shell,Userinit,Taskman,AppSetup,GinaDLL,VmApplet
    'Notify:'; Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify' | Select-Object -ExpandProperty PSChildName
}
Run 'LSA packages' {
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' | Format-List 'Authentication Packages','Notification Packages','Security Packages'
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig' | Format-List 'Security Packages'
}
Run 'IFEO com Debugger (hijack de executavel)' {
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' | ForEach-Object {
        Get-ChildItem $_ | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath
            if ($p.Debugger -or $p.GlobalFlag -or $p.MonitorProcess) { "$($_.PSChildName)  Debugger=$($p.Debugger)  GlobalFlag=$($p.GlobalFlag)  Monitor=$($p.MonitorProcess)" }
        }
    }
}
Run 'Run/RunOnce de TODOS os hives (incl. contas sem sessao)' {
    $keys = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run','SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run','SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    foreach ($k in $keys) {
        $full = "HKLM:\$k"; if (Test-Path $full) { (Get-Item $full).Property | ForEach-Object { "HKLM\$k :: $_ = $((Get-ItemProperty $full).$_)" } }
    }
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object {
        $sid = $_.PSChildName
        $hive = (Get-ItemProperty $_.PSPath).ProfileImagePath + '\NTUSER.DAT'
        if ($sid -match '-1\d{3}$' -and (Test-Path $hive)) {
            $mounted = $false
            if (-not (Test-Path "Registry::HKEY_USERS\$sid")) { reg load "HKU\AUD_$sid" $hive 2>$null | Out-Null; $root="Registry::HKEY_USERS\AUD_$sid"; $mounted=$true }
            else { $root = "Registry::HKEY_USERS\$sid" }
            foreach ($k in $keys) {
                $full = "$root\$k"
                if (Test-Path $full) { (Get-Item $full).Property | ForEach-Object { "$sid\$k :: $_ = $((Get-ItemProperty $full).$_)" } }
            }
            if ($mounted) { [gc]::Collect(); reg unload "HKU\AUD_$sid" 2>$null | Out-Null }
        }
    }
}
Run 'Pastas Startup de todos os usuarios' {
    Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*',
                  'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*' -Force |
        Select-Object LastWriteTime,Length,FullName | Format-Table -AutoSize
}
Run 'Persistencia WMI (Event Consumers - tecnica furtiva)' {
    'Filtros:'; Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | Select-Object Name,Query
    'Consumers:'; Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer | Select-Object Name,__CLASS,CommandLineTemplate,ScriptText
    'Bindings:'; Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | Select-Object Filter,Consumer
}
Run 'Tarefas agendadas nao-Microsoft (com autor e conta)' {
    Get-ScheduledTask | Where-Object TaskPath -notlike '\Microsoft*' | ForEach-Object {
        $i = $_ | Get-ScheduledTaskInfo
        [pscustomobject]@{
            Tarefa  = $_.TaskPath + $_.TaskName
            Estado  = $_.State
            Autor   = $_.Author
            Conta   = $_.Principal.UserId
            RunLvl  = $_.Principal.RunLevel
            UltExec = $i.LastRunTime
            Acao    = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
        }
    } | Sort-Object Tarefa | Format-Table -Wrap
}
Run 'Arquivos de tarefa alterados nos ultimos 60 dias' {
    Get-ChildItem 'C:\Windows\System32\Tasks' -Recurse -File |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-60) } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 40 LastWriteTime,FullName | Format-Table -AutoSize
}
Run 'Servicos com caminho sem aspas e com espaco' {
    Get-CimInstance Win32_Service | Where-Object {
        $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match '^[A-Za-z]:\\[^"]* [^"]*\\'
    } | Select-Object Name,StartName,StartMode,PathName | Format-Table -Wrap
}
Run 'Assinatura dos autoruns (nao assinado = olhar)' -Slow {
    Get-CimInstance Win32_StartupCommand | ForEach-Object {
        $cmd = $_.Command
        $exe = if ($cmd -match '^"([^"]+)"') { $matches[1] } else { ($cmd -split ' ')[0] }
        $exe = [Environment]::ExpandEnvironmentVariables($exe)
        $sig = if (Test-Path $exe) { Get-AuthenticodeSignature $exe } else { $null }
        [pscustomobject]@{
            Nome   = $_.Name
            Status = if ($sig) { $sig.Status } else { 'ARQUIVO NAO ENCONTRADO' }
            Signer = if ($sig) { $sig.SignerCertificate.Subject -replace '^CN=([^,]+).*','$1' } else { '' }
            Exe    = $exe
        }
    } | Sort-Object Status,Nome | Format-Table -AutoSize
}
Run 'Assinatura dos servicos em execucao' -Slow {
    Get-CimInstance Win32_Service | Where-Object State -eq 'Running' | ForEach-Object {
        $exe = if ($_.PathName -match '^"([^"]+)"') { $matches[1] } else { ($_.PathName -split ' ')[0] }
        $sig = if (Test-Path $exe) { Get-AuthenticodeSignature $exe } else { $null }
        [pscustomobject]@{
            Servico = $_.Name
            Conta   = $_.StartName
            Status  = if ($sig) { $sig.Status } else { 'SEM ARQUIVO' }
            Signer  = if ($sig) { $sig.SignerCertificate.Subject -replace '^CN=([^,]+).*','$1' } else { '' }
            Exe     = $exe
        }
    } | Sort-Object { $_.Status -eq 'Valid' }, Servico | Format-Table -AutoSize
}
Run 'Drivers de terceiros carregados' -Slow {
    Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq 'Running' -and $_.PathName -notmatch '(?i)\\system32\\drivers\\(ms|wd|tcpip|http|afd|net|usb|hid|acpi|disk|volume|partmgr|storahci|ks|win)' } |
        ForEach-Object {
            $p = [Environment]::ExpandEnvironmentVariables($_.PathName)
            $sig = if (Test-Path $p) { Get-AuthenticodeSignature $p } else { $null }
            [pscustomobject]@{ Driver=$_.Name; Sig= if($sig){$sig.Status}else{'?'}; Signer= if($sig){$sig.SignerCertificate.Subject -replace '^CN=([^,]+).*','$1'}else{''}; Path=$p }
        } | Sort-Object { $_.Sig -eq 'Valid' },Driver | Format-Table -AutoSize
}

# ------------------------------------------------------------ 6. CERTIFICADOS
NovaSecao 6 'CERTIFICADOS RAIZ NAO-PADRAO (interceptacao de TLS)'

Run 'Root CAs da maquina fora da lista de emissores conhecidos' {
    $known = 'Microsoft','DigiCert','GlobalSign','Baltimore','VeriSign','Thawte','GeoTrust','Entrust','COMODO','Sectigo','USERTrust','AddTrust','GoDaddy','Starfield','Certum','SwissSign','QuoVadis','Symantec','AffirmTrust','Amazon','Go Daddy','Hellenic','Buypass','ISRG','Internet Security Research','SecureTrust','XRamp','Actalis','Chambers','Camerfirma','T-TeleSec','D-TRUST','TeliaSonera','Security Communication','SSL.com','Certigna','Hongkong','TWCA','NetLock','E-Tugra','OISTE','WISeKey','Atos','emSign','vTrus','ANF','Certainly','AC RAIZ','Autoridade','ICP-Brasil','Serpro','Certisign','Serasa','AC Soluti','Valid','Sincor','Fenacon','Notarial','Boa Vista','Digital','Link','Instituto','Caixa','Imprensa','SINCOR','SOLUTI','Safeweb','Prodemge','Prodest','Oracle','Thales','SafeNet','Yubico'
    Get-ChildItem Cert:\LocalMachine\Root | ForEach-Object {
        $s = $_.Subject
        if (-not ($known | Where-Object { $s -like "*$_*" })) {
            [pscustomobject]@{ Subject=$s; Emitido=$_.NotBefore; Expira=$_.NotAfter; Thumbprint=$_.Thumbprint }
        }
    } | Format-List
}
Run 'Root CAs com NotBefore nos ultimos 24 meses' {
    Get-ChildItem Cert:\LocalMachine\Root | Where-Object NotBefore -gt (Get-Date).AddMonths(-24) |
        Select-Object Subject,NotBefore,NotAfter,Thumbprint | Format-List
}
Run 'Root CAs no store do USUARIO (mais facil de plantar)' {
    Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Subject -notmatch 'Microsoft|DigiCert|VeriSign|Thawte|GlobalSign|Baltimore|ICP-Brasil|Certisign|SOLUTI|Serpro|Valid|Safeweb' } |
        Select-Object Subject,NotBefore,NotAfter,Thumbprint | Format-List
}

# -------------------------------------------------------------- 7. REDE
NovaSecao 7 'REDE, ACESSO REMOTO, COMPARTILHAMENTOS'

Run 'RDP - estado e hardening' {
    Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' | Format-List fDenyTSConnections,fSingleSessionPerUser
    Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' | Format-List UserAuthentication,SecurityLayer,MinEncryptionLevel,PortNumber
    'Remote Desktop Users:'; net localgroup "Remote Desktop Users"
}
Run 'WinRM / PSRemoting' {
    Get-Service WinRM | Select-Object Status,StartType
    winrm get winrm/config/service 2>&1
    'Listeners:'; winrm enumerate winrm/config/listener 2>&1
}
Run 'OpenSSH - config efetiva, grupo e chaves' {
    'sshd -T (config efetiva):'
    $exe = "$env:SystemRoot\System32\OpenSSH\sshd.exe"
    if (-not (Test-Path $exe)) { $exe = "$env:ProgramFiles\OpenSSH\sshd.exe" }
    if (Test-Path $exe) { & $exe -T 2>&1 } else { 'sshd.exe nao encontrado' }
    'OpenSSH Users group:'; net localgroup "OpenSSH Users"
    'administrators_authorized_keys:'
    Get-Content 'C:\ProgramData\ssh\administrators_authorized_keys'
    'authorized_keys por perfil:'
    Get-ChildItem 'C:\Users\*\.ssh\authorized_keys' -Force | ForEach-Object { "--- $($_.FullName)  (mod $($_.LastWriteTime))"; Get-Content $_.FullName }
}
Run 'Logs de autenticacao SSH  <<< ALGUEM ENTROU?' {
    Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 100 |
        Select-Object TimeCreated,Id,@{n='Msg';e={($_.Message -split "`r?`n")[0]}} | Format-Table -Wrap
}
Run 'Compartilhamentos e permissoes' {
    Get-SmbShare | ForEach-Object {
        "[$($_.Name)] -> $($_.Path)"
        $_ | Get-SmbShareAccess | ForEach-Object { "    $($_.AccountName)  $($_.AccessRight)  $($_.AccessControlType)" }
    }
}
Run 'Sessoes SMB e arquivos abertos agora' {
    Get-SmbSession | Select-Object ClientComputerName,ClientUserName,NumOpens,SecondsExists | Format-Table -AutoSize
    Get-SmbOpenFile | Select-Object ClientComputerName,ClientUserName,Path | Format-Table -AutoSize
}
Run 'Config SMB servidor e cliente' {
    Get-SmbServerConfiguration | Format-List EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,EnableSecuritySignature,EncryptData,RejectUnencryptedAccess,RestrictNamedPipeAccess,AutoShareServer,AutoShareWorkstation
    Get-SmbClientConfiguration | Format-List RequireSecuritySignature,EnableSecuritySignature,EnableInsecureGuestLogons,BlockNTLM
}
Run 'Firewall: regras inbound ALLOW habilitadas (com programa)' {
    Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | ForEach-Object {
        $af = $_ | Get-NetFirewallApplicationFilter
        $pf = $_ | Get-NetFirewallPortFilter
        $ad = $_ | Get-NetFirewallAddressFilter
        [pscustomobject]@{
            Regra   = $_.DisplayName
            Perfil  = $_.Profile
            Proto   = $pf.Protocol
            Porta   = ($pf.LocalPort -join ',')
            RemIP   = ($ad.RemoteAddress -join ',')
            Programa= $af.Program
        }
    } | Sort-Object Regra | Format-Table -Wrap
}
Run 'Conexoes atuais com processo e caminho' {
    Get-NetTCPConnection -State Established,Listen | ForEach-Object {
        $pr = Get-Process -Id $_.OwningProcess
        [pscustomobject]@{ Est=$_.State; Local="$($_.LocalAddress):$($_.LocalPort)"; Remoto="$($_.RemoteAddress):$($_.RemotePort)"; Proc=$pr.ProcessName; Path=$pr.Path }
    } | Sort-Object Proc | Format-Table -Wrap
}
Run 'Port proxy (netsh) e rotas' { netsh interface portproxy show all; route print -4 }
Run 'Perfis Wi-Fi' { netsh wlan show profiles }

# ------------------------------------------------- 8. ACESSO REMOTO / RMM
NovaSecao 8 'FERRAMENTAS DE ACESSO REMOTO E RMM'

Run 'Varredura de RMM / acesso remoto conhecidos' {
    $pat = 'action1|teamviewer|anydesk|logmein|lmi_|rescue|screenconnect|connectwise|splashtop|dwagent|ammyy|supremo|vnc|radmin|atera|ninja|rmm|syncro|datto|kaseya|pulseway|gotoassist|bomgar|beyondtrust|zoho|assist|remoteutil|rustdesk|meshagent|tacticalrmm|itarian|solarwinds|take?control'
    'SERVICOS:'
    Get-CimInstance Win32_Service | Where-Object { $_.Name -match $pat -or $_.DisplayName -match $pat -or $_.PathName -match $pat } |
        Select-Object Name,DisplayName,State,StartMode,StartName,PathName | Format-List
    'PROCESSOS:'
    Get-Process | Where-Object { $_.ProcessName -match $pat -or $_.Path -match $pat } | Select-Object ProcessName,Id,Path,StartTime | Format-Table -AutoSize
    'TAREFAS:'
    Get-ScheduledTask | Where-Object { $_.TaskName -match $pat -or ($_.Actions.Execute -join ' ') -match $pat } | Select-Object TaskPath,TaskName,State | Format-Table -AutoSize
}
if ($RmmVendor) {
    # Detalhe do agente de RMM/gestao que a empresa (ou voce) instalou de
    # proposito. Passe o nome em -RmmVendor, ex.: -RmmVendor 'action1'.
    $rmmDirs = @(
        (Join-Path $env:ProgramFiles $RmmVendor),
        (Join-Path ${env:ProgramFiles(x86)} $RmmVendor),
        (Join-Path $env:ProgramData $RmmVendor)
    ) | Where-Object { Test-Path $_ }

    Run "$RmmVendor - detalhe do agente" {
        Get-CimInstance Win32_Service -Filter "Name LIKE '%$RmmVendor%'" | Format-List Name,DisplayName,State,StartMode,StartName,PathName
        # O -Recurse aqui travava o script: agentes de RMM cacheiam catalogo de
        # patches no registro (dezenas de milhares de subchaves). Depth 1 + limite.
        Get-ChildItem "HKLM:\SOFTWARE\$RmmVendor","HKLM:\SOFTWARE\WOW6432Node\$RmmVendor" -Depth 1 |
            Select-Object -First 50 |
            ForEach-Object { $k=$_; $k.Property | Select-Object -First 30 | ForEach-Object { "$($k.PSChildName) :: $_ = $((Get-ItemProperty $k.PSPath).$_)" } }
    }

    if ($SuspectAccount -and $rmmDirs) {
        Run "$RmmVendor criou a conta $SuspectAccount? (busca por referencias)" {
            "Referencias a $SuspectAccount em arquivos de config/log do ${RmmVendor}:"
            Get-ChildItem $rmmDirs -Recurse -File -Include *.log,*.txt,*.json,*.xml,*.ini -Depth 4 |
                Select-String -Pattern $SuspectAccount -SimpleMatch | Select-Object -First 25 Path,LineNumber,Line | Format-Table -Wrap
            if ($IncidentDate) {
                $d0 = ([datetime]$IncidentDate).AddDays(-2); $d1 = ([datetime]$IncidentDate).AddDays(2)
                "Arquivos do $RmmVendor modificados entre $($d0.ToString('yyyy-MM-dd')) e $($d1.ToString('yyyy-MM-dd')):"
                Get-ChildItem $rmmDirs -Recurse -File -Depth 4 |
                    Where-Object { $_.LastWriteTime -gt $d0 -and $_.LastWriteTime -lt $d1 } |
                    Select-Object LastWriteTime,FullName | Format-Table -AutoSize
            }
        }
    }
}
Run 'VNC - vestigios (servicos, regras de firewall, pastas)' {
    Get-NetFirewallRule -DisplayName 'vnc*' | ForEach-Object { $af=$_|Get-NetFirewallApplicationFilter; "$($_.DisplayName) enabled=$($_.Enabled) perfil=$($_.Profile) prog=$($af.Program)" }
    Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'vnc' -or $_.PathName -match '(?i)vnc' } | Format-List Name,State,PathName
    Get-ChildItem 'C:\Program Files','C:\Program Files (x86)' -Directory | Where-Object Name -match 'vnc|ultra|tight|real' | Select-Object FullName,CreationTime
}

# ---------------------------------------------------- 9. ATUALIZACOES / GPO
NovaSecao 9 'ATUALIZACOES, POLITICAS E INTEGRIDADE'

Run 'Politicas de Windows Update (indicam gestao externa/RMM)' {
    Get-ChildItem 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Recurse |
        ForEach-Object { $k=$_; $k.Property | ForEach-Object { "$($k.PSPath -replace '.*WindowsUpdate','WU') :: $_ = $((Get-ItemProperty $k.PSPath).$_)" } }
}
Run 'Updates pendentes e reboot pendente' -Slow {
    $s = New-Object -ComObject Microsoft.Update.Session
    $r = $s.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software'")
    $r.Updates | Select-Object Title,@{n='Severity';e={$_.MsrcSeverity}},IsDownloaded | Format-Table -AutoSize
    'Reboot pendente:'
    [pscustomobject]@{
        CBS  = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        WU   = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        Ren  = [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager').PendingFileRenameOperations
    } | Format-List
}
Run 'Servicos/drivers instalados recentemente (evento 7045)' {
    Get-WinEvent -FilterHashtable @{LogName='System';Id=7045} -MaxEvents 60 |
        Select-Object TimeCreated,@{n='Msg';e={($_.Message -split "`r?`n" | Where-Object {$_ -match '\S'}) -join ' | '}} | Format-Table -Wrap
}
Run 'Instalacoes de software (MsiInstaller, 90 dias)' -Slow {
    Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='MsiInstaller';StartTime=(Get-Date).AddDays(-90)} -MaxEvents 100 |
        Select-Object TimeCreated,@{n='Msg';e={($_.Message -split "`r?`n")[0]}} | Format-Table -Wrap
}
Run 'PowerShell 4104 - scriptblocks suspeitos (30 dias)' -Slow {
    # Padroes remontados em runtime: se as assinaturas ficarem literais no arquivo,
    # o proprio AMSI/Defender bloqueia a leitura deste script (aconteceu na v1.0).
    $pat = @(
        @('From','Base64','String'), @('Download','String'), @('Download','File'),
        @('Invoke','-Expression'),   @('-Encoded','Command'), @('Net\.Web','Client'),
        @('Start-Bits','Transfer'),  @('bits','admin'),       @('cert','util.*-urlcache'),
        @('mimi','katz'),            @('amsi','InitFailed'),  @('Virtual','Alloc'),
        @('Reflection\.','Assembly'),@('Add-MpPreference.*Ex','clusion'),
        @('Set-MpPreference.*Dis','able'), @('I','EX\b')
    ) | ForEach-Object { -join $_ }
    $pat = $pat -join '|'

    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=(Get-Date).AddDays(-7)} -MaxEvents 1500 |
        Where-Object { $_.Message -match $pat } |
        Select-Object TimeCreated,
            @{n='Bate';e={ ([regex]::Matches($_.Message,$pat) | ForEach-Object { $_.Value } | Select-Object -Unique) -join ',' }},
            @{n='Trecho';e={ ($_.Message -replace "`r?`n",' ').Substring(0,[Math]::Min(200,$_.Message.Length)) }} |
        Format-Table -Wrap
}
Run 'Politicas aplicadas (gpresult)' -Slow { gpresult /scope computer /r }
Run 'DISM /ScanHealth (so verificacao, nao repara)' -Slow {
    DISM /Online /Cleanup-Image /ScanHealth
}

# ------------------------------------------------- 10. ARQUIVOS SUSPEITOS
NovaSecao 10 'ARQUIVOS E LOCAIS COMUNS DE MALWARE'

Run 'Executaveis em Temp/Downloads/ProgramData/Public' -Slow {
    $paths = 'C:\Users\*\AppData\Local\Temp','C:\Users\*\Downloads','C:\ProgramData','C:\Windows\Temp','C:\Users\Public'
    Get-ChildItem $paths -Include *.exe,*.dll,*.scr,*.ps1,*.bat,*.cmd,*.vbs,*.js,*.jar,*.hta -Recurse -Force -Depth 3 |
        Where-Object { $_.Length -gt 0 } | Sort-Object LastWriteTime -Descending | Select-Object -First 60 |
        ForEach-Object {
            $sig = Get-AuthenticodeSignature $_.FullName
            [pscustomobject]@{ Data=$_.LastWriteTime; KB=[int]($_.Length/1KB); Sig=$sig.Status; Signer=($sig.SignerCertificate.Subject -replace '^CN=([^,]+).*','$1'); Arquivo=$_.FullName }
        } | Format-Table -Wrap
}
Run 'Origem dos downloads recentes (Zone.Identifier)' {
    Get-ChildItem 'C:\Users\*\Downloads' -File -Force -Recurse -Depth 2 |
        Sort-Object LastWriteTime -Descending | Select-Object -First 30 | ForEach-Object {
            $z = Get-Content "$($_.FullName):Zone.Identifier" -ErrorAction SilentlyContinue
            $url = ($z | Where-Object { $_ -match 'HostUrl|ReferrerUrl' }) -join ' '
            "{0}  {1}  {2}" -f $_.LastWriteTime, $_.Name, $url
        }
}
Run 'Extensoes de navegador (Chrome/Edge/Brave)' {
    Get-ChildItem 'C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Extensions\*',
                  'C:\Users\*\AppData\Local\Microsoft\Edge\User Data\*\Extensions\*',
                  'C:\Users\*\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Extensions\*' -Directory |
        ForEach-Object {
            $id = $_.Name
            $m = Get-ChildItem $_.FullName -Directory | Select-Object -First 1
            $mj = Join-Path $m.FullName 'manifest.json'
            $nm=''; $pm=''
            if (Test-Path $mj) { $j = Get-Content $mj -Raw | ConvertFrom-Json; $nm=$j.name; $pm=($j.permissions -join ',') }
            "{0}  [{1}]  nome={2}  perms={3}" -f ($_.FullName -replace '.*User Data\\',''), $id, $nm, $pm
        }
}
Run 'Extensoes forcadas por politica' {
    Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist',
                     'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist' | Format-List
}
Run 'Atalhos .lnk com alvo suspeito' {
    $sh = New-Object -ComObject WScript.Shell
    $alvo  = '(?i)powershell|cmd\.exe|msh' + 'ta|rund' + 'll32|wscript|cscript|curl|cert' + 'util'
    $argp  = '(?i)http|-enc\b|base' + '64|I' + 'EX\b'
    Get-ChildItem 'C:\Users\*\Desktop\*.lnk','C:\Users\Public\Desktop\*.lnk' -Force | ForEach-Object {
        $l = $sh.CreateShortcut($_.FullName)
        if ($l.TargetPath -match $alvo -or $l.Arguments -match $argp) {
            "{0}`n    target={1}`n    args={2}" -f $_.FullName,$l.TargetPath,$l.Arguments
        }
    }
}

# ---------------------------------------------------------------- FIM
W ''
W ('=' * 78)
W '## FIM'
W ('=' * 78)
W "Concluido em: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
W ("Duracao total: {0:N1} min" -f ((Get-Date) - $script:t0).TotalMinutes)

Close-Log
Copy-Item $live $final -Force

Write-Host ''
Write-Host ("CONCLUIDO em {0:N1} min" -f ((Get-Date) - $script:t0).TotalMinutes) -ForegroundColor Green
Write-Host "   $live"
Write-Host "   $final"
Write-Host 'Nada foi alterado no sistema - a coleta e somente leitura.' -ForegroundColor Cyan
