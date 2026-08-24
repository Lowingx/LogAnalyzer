#!/usr/bin/env bash
# live_attack.sh — gerador de ataque SSH em tempo real para demonstrações
# uso: ./live_attack.sh [arquivo_saída]   (default: /tmp/live_auth.log)
# Ctrl+C para. Cada linha chega com pausa humana (1–4s). O padrão é sempre diferente.

OUT="${1:-/tmp/live_auth.log}"
: > "$OUT"

ATTACKERS=("45.83.66.$((RANDOM%250))" "185.220.101.$((RANDOM%99))" "91.240.118.17" "103.75.190.$((RANDOM%99))")
USERS_BAD=(root admin oracle postgres pi guest test ubuntu backup git ftpuser)
USERS_OK=(deploy admin)
T0=$(date +%s)

log() { echo "$(date '+%b %d %H:%M:%S') srv01 sshd[$((RANDOM%6000+1000))]: $*" >> "$OUT"; }

pause() { sleep $((RANDOM % 3 + 1)); }

echo "[*] atacando $OUT — Ctrl+C para" >&2
while true; do
    # tráfego benigno ocasional (30%)
    if [ $((RANDOM % 10)) -lt 3 ]; then
        u=${USERS_OK[$((RANDOM % ${#USERS_OK[@]}))]}
        log "Accepted publickey for $u from 192.168.1.24 port $((RANDOM%999+40000)) ssh2"
        pause; continue
    fi

    atk=${ATTACKERS[$((RANDOM % ${#ATTACKERS[@]}))]}

    case $((RANDOM % 10)) in
        0|1|2|3|4|5)  # rajada de brute-force
            n=$((RANDOM % 6 + 3))
            for _ in $(seq $n); do
                u=${USERS_BAD[$((RANDOM % ${#USERS_BAD[@]}))]}
                log "Failed password for invalid user $u from $atk port $((RANDOM%999+40000)) ssh2"
                pause
            done
            ;;
        6|7)          # momento crítico: falhou muito e ENTROU
            u=${USERS_BAD[$((RANDOM % ${#USERS_BAD[@]}))]}
            for _ in $(seq $((RANDOM % 4 + 5))); do
                log "Failed password for $u from $atk port $((RANDOM%999+40000)) ssh2"
                pause
            done
            log "Accepted password for $u from $atk port $((RANDOM%999+40000)) ssh2"
            pause
            ;;
        8)            # enumeração de usuários
            for u in "${USERS_BAD[@]:0:$((RANDOM % 3 + 2))}"; do
                log "Invalid user $u from $atk port $((RANDOM%999+40000))"
                pause
            done
            ;;
        9)            # login legítimo isolado
            log "Accepted publickey for deploy from 10.0.0.5 port $((RANDOM%999+40000)) ssh2"
            ;;
    esac
done
