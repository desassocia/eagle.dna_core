#!/data/data/com.termux/files/usr/bin/bash
set -eu
cd "$(dirname "$0")"
echo "[ eagle.dna_core ] preparando ambiente..."
if ! command -v python >/dev/null 2>&1; then
  echo "Python não encontrado. Execute: pkg install python -y"
  exit 1
fi
mkdir -p data/samples data/reports
echo "Instalação concluída. Iniciando..."
python main.py
