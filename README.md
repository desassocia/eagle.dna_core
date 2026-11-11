# eagle.dna_core

Painel de diagnóstico **local** para Termux, com interface de terminal preta e verde.

## Instalação no Termux

    pkg install git python -y
    git clone https://github.com/desassocia/eagle.dna_core.git
    cd eagle.dna_core
    bash install.sh

Para abrir novamente:

    cd ~/eagle.dna_core
    python main.py

## Módulos

- analyze.files e deep.scan: procuram palavras-chave em arquivos de texto dentro de data/samples.
- proxy.analysis: mostra se existem variáveis locais de proxy.
- dns.monitor: tenta ler a configuração DNS local.
- ip.intelligence: exemplo com endereço reservado para documentação.
- remote.access: informa que o projeto opera apenas localmente.
- dma.bypass: tela demonstrativa; não contorna proteções.
- file.database, scan.history, reports.center e system.info: organização e informações locais.
- clear.all: limpa somente a tela, sem apagar dados.

## Segurança e limitações

Este projeto não acessa memória de jogos, não injeta código, não contorna anti-cheat, não controla dispositivos remotos e não faz varreduras de rede. Resultados de palavras-chave são indicadores de texto, não prova de comprometimento. Relatórios ficam em data/reports.

Requer Python 3. Não usa bibliotecas externas.
