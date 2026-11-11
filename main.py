#!/usr/bin/env python3
from __future__ import annotations
import json, os, platform, socket, sys, random
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
SAMPLES = DATA / "samples"
LAB = DATA / "lab_generated"
REPORTS = DATA / "reports"
HISTORY = DATA / "scan_history.json"
SUPPORTED = {".txt", ".log", ".json", ".ini", ".cfg", ".csv", ".md"}
MARKERS = ("injector", "memory modification", "suspicious connection", "proxy",
           "dns configuration change", "remote access", "dma")
GREEN, RESET, DIM = "\033[92m", "\033[0m", "\033[90m"

def setup():
    for folder in (SAMPLES, REPORTS):
        folder.mkdir(parents=True, exist_ok=True)
    sample = SAMPLES / "example_config.txt"
    if not sample.exists():
        sample.write_text("EAGLE DNA CORE demo file\nHarmless local sample.\nproxy: example setting\n", encoding="utf-8")
    if not HISTORY.exists():
        HISTORY.write_text("[]", encoding="utf-8")

def clear_screen():
    os.system("clear" if os.name != "nt" else "cls")

def banner():
    print(GREEN + r"""
   _____   _____ _      ______
  | ____| / ____| |    |  ____|
  | |__  | |  __| |    | |__
  |  __| | | |_ | |    |  __|
  | |____| |__| | |____| |____
  |______|\_____|______|______|
          d n a _ c o r e
""" + RESET)
    print(DIM + " LOCAL DIAGNOSTICS • SAFE DEMO BUILD" + RESET)
    print("─" * 52)

def pause():
    input("\nEnter para voltar ao menu...")

def add_history(entry):
    try:
        records = json.loads(HISTORY.read_text(encoding="utf-8"))
        if not isinstance(records, list):
            records = []
    except (OSError, json.JSONDecodeError):
        records = []
    records.append(entry)
    HISTORY.write_text(json.dumps(records[-100:], indent=2, ensure_ascii=False), encoding="utf-8")

def scan_files():
    print(GREEN + "\n[ analyze.files ]" + RESET)
    found, checked = [], 0
    for source_root in (SAMPLES, LAB):
        if not source_root.exists():
            continue
        for path in source_root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in SUPPORTED:
                continue
            try:
                if path.stat().st_size > 1_000_000:
                    continue
                content = path.read_text(encoding="utf-8", errors="replace").lower()
                checked += 1
                hits = [word for word in MARKERS if word in content]
                if hits:
                    found.append({"file": str(path.relative_to(ROOT)), "indicators": hits})
            except OSError as exc:
                print(f"[!] Erro lendo {path.name}: {exc}")
    entry = {"time": datetime.now().isoformat(timespec="seconds"),
             "files_checked": checked, "matches": found}
    add_history(entry)
    report = REPORTS / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    report.write_text(json.dumps(entry, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Arquivos analisados: {checked}")
    print(f"Arquivos com palavras-chave: {len(found)}")
    for item in found:
        print(f" • {item['file']}: {', '.join(item['indicators'])}")
    print(DIM + "Indicadores de texto não provam atividade maliciosa." + RESET)
    print(f"Relatório salvo: {report.relative_to(ROOT)}")

def deep_scan():
    print(GREEN + "\n[ deep.scan ]" + RESET)
    print("Análise detalhada das amostras locais do projeto.")
    scan_files()

def proxy_analysis():
    print(GREEN + "\n[ proxy.analysis ]" + RESET)
    names = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
    present = [name for name in names if os.environ.get(name)]
    print("Variáveis detectadas:", ", ".join(present) if present else "nenhuma")
    print("Nenhuma conexão externa será iniciada.")

def dns_monitor():
    print(GREEN + "\n[ dns.monitor ]" + RESET)
    for path in (Path("/etc/resolv.conf"), Path("/system/etc/resolv.conf")):
        if path.exists():
            try:
                lines = [x.strip() for x in path.read_text(errors="replace").splitlines()
                         if x.strip().startswith("nameserver")]
                if lines:
                    print(f"Configuração local ({path}):")
                    for line in lines:
                        print(" ", line)
                    return
            except OSError:
                pass
    print("Configuração DNS local indisponível para leitura.")

def ip_intelligence():
    print(GREEN + "\n[ ip.intelligence ]" + RESET)
    print("Exemplo reservado para documentação: 203.0.113.42")
    print("Sem geolocalização ou consulta externa.")

def remote_status():
    print(GREEN + "\n[ remote.access ]" + RESET)
    print("Estado: diagnóstico somente local.")
    print("Este programa não acessa nem controla dispositivos remotos.")

def dma_demo():
    print(GREEN + "\n[ dma.bypass ]" + RESET)
    print("MODO DEMONSTRAÇÃO — nenhum bypass é executado.")
    print("Contorno de proteções: não implementado.")

def system_info():
    print(GREEN + "\n[ system.info ]" + RESET)
    print("Sistema:", platform.system(), platform.release())
    print("Arquitetura:", platform.machine())
    print("Python:", sys.version.split()[0])
    print("Dispositivo:", socket.gethostname())

def reports_center():
    print(GREEN + "\n[ reports.center ]" + RESET)
    reports = sorted(REPORTS.glob("*.json"), reverse=True)
    if not reports:
        print("Nenhum relatório criado.")
    for report in reports[:15]:
        print(" •", report.name)

def scan_history():
    print(GREEN + "\n[ scan.history ]" + RESET)
    try:
        records = json.loads(HISTORY.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        records = []
    if not records:
        print("Histórico vazio.")
    for item in records[-10:][::-1]:
        print(f" • {item.get('time', '?')} | arquivos: {item.get('files_checked', 0)} | indicadores: {len(item.get('matches', []))}")

def file_database():
    print(GREEN + "\n[ file.database ]" + RESET)
    files = [p for root in (SAMPLES, LAB) if root.exists()
             for p in root.rglob("*") if p.is_file()]
    print(f"Arquivos locais de demonstração: {len(files)}")
    for path in files[:40]:
        print(" •", path.relative_to(ROOT))
    if len(files) > 40:
        print(f" ... e mais {len(files) - 40} arquivos.")

def generate_lab_files():
    folders = ("logs", "configs", "reports", "events", "cache")
    extensions = (".txt", ".log", ".json", ".ini", ".cfg", ".csv", ".md")
    messages = (
        "status=simulation_only", "event=sample_created",
        "proxy=demo.local", "dns=192.0.2.53",
        "remote_access=disabled", "dma_bypass=not_implemented",
        "result=harmless_test_record", "integrity=demo"
    )
    total = 120
    print(GREEN + "\n[ lab.generate ]" + RESET)
    print("Criando 120 arquivos fictícios em data/lab_generated/")
    print("Tudo ficará dentro da pasta do projeto.\n")
    created = 0
    for i in range(1, total + 1):
        folder = LAB / folders[(i - 1) % len(folders)]
        folder.mkdir(parents=True, exist_ok=True)
        ext = extensions[(i - 1) % len(extensions)]
        path = folder / f"sample_{i:03d}{ext}"
        stamp = datetime.now().isoformat(timespec="seconds")
        if ext == ".json":
            content = json.dumps({"id": i, "timestamp": stamp, "mode": "fictional",
                                  "records": random.sample(messages, 3)}, indent=2)
        elif ext == ".csv":
            content = "id,timestamp,event\n" + f"{i},{stamp},sample_created\n"
        else:
            content = (f"EAGLE DNA CORE / FICTIONAL LAB\nID={i:03d}\nTIME={stamp}\n"
                       + "\n".join(random.sample(messages, 4)) + "\n")
        path.write_text(content, encoding="utf-8")
        created += 1
        if i % 10 == 0 or i == total:
            bar = "#" * (i // 5) + "-" * (24 - i // 5)
            print(f" [{bar}] {i:3}/{total} | {path.relative_to(ROOT)}")
    summary = {"created": created, "folder": str(LAB.relative_to(ROOT)),
               "time": datetime.now().isoformat(timespec="seconds"), "type": "fictional_demo"}
    (LAB / "generation_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(GREEN + f"\n[ OK ] {created} arquivos fictícios criados." + RESET)
    print("Agora use 8 para listar ou 1 para analisar as amostras.")

def menu():
    actions = {
        "1": ("analyze.files", scan_files), "2": ("deep.scan", deep_scan),
        "3": ("proxy.analysis", proxy_analysis), "4": ("dns.monitor", dns_monitor),
        "5": ("ip.intelligence", ip_intelligence), "6": ("remote.access", remote_status),
        "7": ("dma.bypass", dma_demo), "8": ("file.database", file_database),
        "9": ("scan.history", scan_history), "10": ("reports.center", reports_center),
        "11": ("system.info", system_info), "13": ("lab.generate", generate_lab_files)
    }
    while True:
        clear_screen()
        banner()
        for key, (label, _) in actions.items():
            print(f" {key:>2}. {label}")
        print(" 12. clear.all\n  0. system.exit")
        choice = input("\n eagle@termux:~$ ").strip().lower()
        if choice == "0":
            print(GREEN + "system.status: encerrado com segurança" + RESET)
            break
        if choice == "12":
            clear_screen()  # limpa somente a tela; não apaga arquivos
            continue
        action = actions.get(choice)
        if action:
            action[1]()
            pause()
        else:
            print("Opção inválida.")
            pause()

if __name__ == "__main__":
    setup()
    menu()
