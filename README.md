# win11-security-audit

Dois scripts PowerShell de **auditoria somente leitura** de uma estacao Windows 11.
Eles nao alteram nada no sistema: coletam estado de seguranca e gravam um relatorio
em texto para analise posterior.

| Script | Elevacao | O que cobre |
| --- | --- | --- |
| `Audit-Security-admin-latest.ps1` | **Administrador** | 10 secoes: contas e grupos, log de seguranca, Defender (exclusoes/ASR/ameacas), boot/TPM/BitLocker/VBS, persistencia, certificados raiz nao-padrao, rede e compartilhamentos, acesso remoto e RMM, atualizacoes e politicas, locais comuns de malware |
| `Audit-Security-non-admin-latest.ps1` | **Nao precisa** | Origem dos downloads (`Zone.Identifier`) em todos os drives e extensoes de navegador de todos os perfis acessiveis |

O segundo script existe porque essas duas verificacoes costumam ficar incompletas:
a pasta de downloads muitas vezes nao e `C:\Users\<voce>\Downloads`, e a varredura de
extensoes normalmente cobre apenas o perfil que esta logado. Ele roda sem elevacao,
detecta o que nao conseguiu ler e diz no fim exatamente o que ficou de fora e por que.
Rodando elevado, cobre tudo.

---

## Privacidade: o que este repositorio NAO contem

Este repositorio carrega **apenas os scripts e este README**. Nenhum resultado de
execucao, de nenhuma maquina, e versionado aqui — e esse e um requisito do projeto,
nao um detalhe.

Os relatorios revelam contas locais, caminhos, exclusoes de antivirus, politicas,
eventos de logon, extensoes de navegador e nomes de arquivo. Publicar um deles e
entregar um mapa da maquina.

Por isso:

- Os dois scripts gravam **sempre** em `.\log\`, e `log/` esta no `.gitignore`.
- O `.gitignore` tambem ignora, na raiz, `*.txt`, `*.log`, `*.csv`, `*.json`, `*.xml`,
  `*.evtx`, `*.zip`, `RELATORIO*.md` e `analise*.md`.
- `Fix-*.ps1` esta ignorado: scripts de remediacao alteram o sistema e sao escritos
  para um achado especifico de uma maquina especifica. Eles ficam locais.
- Antes de qualquer commit, confira o que esta sendo enviado:

```bash
git status --porcelain && git diff --cached --stat
```

Se um relatorio precisar ser compartilhado com alguem, mande o arquivo por outro
canal e **sanitize antes**: nomes de usuario, nome da maquina, caminhos pessoais,
seriais e enderecos de rede.

---

## Como usar em outra maquina

1. Clone o repositorio em uma pasta de trabalho local:

```bash
git clone https://github.com/t3n-br/win11-security-audit.git
```

2. Rode a parte sem elevacao (PowerShell comum, na pasta do repo):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Audit-Security-non-admin-latest.ps1
```

3. Rode a parte elevada (PowerShell **como Administrador**, na pasta do repo):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Audit-Security-admin-latest.ps1
```

4. Leia os relatorios em `.\log\`. Eles sao gravados **ao vivo, etapa a etapa**: se
   voce interromper com Ctrl+C, tudo o que ja rodou esta no arquivo.

Requisitos: Windows 11 (funciona no 10), PowerShell 5.1 — que e o que vem no sistema.
Os scripts nao instalam nada e nao acessam a rede.

### Teste rapido antes de rodar de verdade

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Audit-Security-admin-latest.ps1 -SelfTest
```

`-SelfTest` so carrega o script (prova que passou pelo AMSI/antivirus) e sai sem coletar nada.

### Opcoes uteis

`Audit-Security-admin-latest.ps1`:

| Parametro | Para que serve |
| --- | --- |
| `-SkipSlow` | Pula as 4 etapas pesadas (DISM e varreduras de assinatura em disco) |
| `-OnlySection 9,10` | Roda apenas as secoes indicadas (1..10) |
| `-SuspectAccount 'ADMIN_exemplo'` | Detalha uma conta local especifica e o perfil dela |
| `-RmmVendor 'action1'` | Detalha o agente de RMM/gestao com esse nome (servico, registro, logs) |
| `-IncidentDate '2026-09-30'` | Janela de +-2 dias usada nas buscas dirigidas acima |
| `-SelfTest` | So carrega e sai |

Os tres parametros de investigacao vem **desligados**. Sem eles o script faz a coleta
generica, sem procurar nada especifico de maquina nenhuma.

`Audit-Security-non-admin-latest.ps1`:

| Parametro | Para que serve |
| --- | --- |
| `-Dias 365` | Janela dos downloads analisados (padrao: 180) |
| `-MaxArquivos 150` | Teto de arquivos listados por pasta (padrao: 80) |
| `-PastaExcluida 'F:\Save','D:\Tools'` | Lista o conteudo executavel de pastas que estao nas exclusoes do Defender |
| `-SelfTest` | So carrega e sai |

Exemplo tipico:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Audit-Security-admin-latest.ps1 -SkipSlow
```

---

## Analise e ajuste com Claude Code

A coleta e so metade do trabalho: o relatorio tem centenas de linhas e o que importa
sao as poucas que estao fora do lugar. Use o [Claude Code](https://claude.com/claude-code)
**na sua maquina**, com o relatorio local em maos:

```bash
claude
```

Prompts que funcionam bem:

- `Leia log/audit-latest.txt e liste o que esta fora do padrao, em ordem de risco. Para cada item: por que importa, como confirmar, e qual a correcao.`
- `Compare log/audit-latest.txt com log/audit-20261017-193729.txt e me mostre o que mudou entre as duas execucoes.`
- `Esta maquina tem um cenario diferente (sem TPM / em dominio / com RMM corporativo). Ajuste Audit-Security-admin-latest.ps1 para cobrir isso.`
- `A secao 5 esta lenta nesta maquina. Descubra qual etapa e o gargalo usando os tempos gravados no relatorio.`

Duas coisas valem repetir:

- O relatorio fica **local**. O Claude Code le o arquivo no seu disco; nao commite o
  arquivo para "mostrar" a analise.
- Toda correcao sugerida deve ser revisada por voce antes de aplicar. Se gerar um script
  de remediacao, salve como `Fix-*.ps1` — ja ignorado pelo `.gitignore` — e teste em uma
  maquina que voce possa recuperar.

Melhorias **genericas** nos scripts (uma verificacao nova, um bug, uma etapa mais rapida)
sao bem-vindas via commit. Qualquer coisa amarrada a uma maquina — nome de conta, letra
de drive, nome de RMM, data de incidente — entra como **parametro**, nunca escrito no
corpo do script. Os parametros existentes servem de modelo.

---

## Nota sobre o Harden System Security

Estes scripts **apenas leem**. Para efetivamente endurecer a configuracao do Windows,
o caminho recomendado e o **Harden System Security**, app open source do projeto
[HotCakeX/Harden-Windows-Security](https://github.com/HotCakeX/Harden-Windows-Security),
distribuido pela Microsoft Store (ID `9P7GGFL7DX57`). Ele aplica hardening usando
mecanismos oficiais da Microsoft e mostra um score de seguranca. Substitui o antigo
modulo PowerShell `Harden-Windows-Security-Module`, hoje marcado como deprecado na
PowerShell Gallery. O mesmo projeto mantem o **AppControl Manager**, GUI para politicas
WDAC/App Control.

Como combinar com este repositorio:

1. Rode a auditoria **antes** e guarde o relatorio (`log/audit-latest.txt`).
2. Aplique o hardening com o Harden System Security.
3. Rode a auditoria **depois** e compare os dois relatorios. Isso mostra o que de fato
   mudou no sistema, em vez de confiar no que a ferramenta diz ter mudado.

Avisos honestos: varias opcoes do app sao agressivas e podem quebrar compatibilidade ou
afetar privacidade/telemetria de formas que talvez voce nao queira. Leia o que cada item
faz, aplique em etapas, tenha ponto de restauracao, e nao rode hardening em massa em
maquina de producao sem janela de manutencao. Em maquina gerenciada pela empresa (MDM,
GPO, RMM), hardening local pode conflitar com a politica central — alinhe antes.

---

## Licenca e escopo

Uso em maquinas que voce administra ou tem autorizacao explicita para auditar.
Os scripts sao somente leitura, mas leem estado sensivel do sistema: rodar isso na
maquina de terceiros sem permissao nao e auditoria.
