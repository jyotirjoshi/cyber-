#!/usr/bin/env bash
# ==============================================================================
# Cynux Production & Cloud Deployment Script
# ==============================================================================
set -euo pipefail

COLOR_RESET="\033[0m"
COLOR_GREEN="\033[32m"
COLOR_CYAN="\033[36m"
COLOR_YELLOW="\033[33m"
COLOR_RED="\033[31m"

echo -e "${COLOR_CYAN}====================================================${COLOR_RESET}"
echo -e "${COLOR_CYAN}           Cynux Platform Deployment                ${COLOR_RESET}"
echo -e "${COLOR_CYAN}====================================================${COLOR_RESET}"

# 1. Check prerequisites
if ! command -v docker &> /dev/null; then
    echo -e "${COLOR_RED}Error: Docker is not installed or not in PATH.${COLOR_RESET}"
    exit 1
fi

if ! docker compose version &> /dev/null; then
    echo -e "${COLOR_RED}Error: Docker Compose v2 plugin is required.${COLOR_RESET}"
    exit 1
fi

# 2. Initialize .env file
if [ ! -f ".env" ]; then
    echo -e "${COLOR_YELLOW}[+] Creating .env from template...${COLOR_RESET}"
    cp .env.example .env
fi

# 3. Generate production secrets
echo -e "${COLOR_GREEN}[+] Generating secure cryptographic secrets...${COLOR_RESET}"
if command -v python3 &> /dev/null; then
    python3 docker/gen-secrets.py
elif command -v python &> /dev/null; then
    python docker/gen-secrets.py
else
    echo -e "${COLOR_YELLOW}[!] Python not found. Using Makefile / fallback secret generation...${COLOR_RESET}"
    make secrets || true
fi

# 4. Check LLM key configuration
LLM_KEY=$(grep "^CYNUX_LLM__ANTHROPIC_API_KEY=" .env | cut -d '=' -f2- || true)
if [ -z "$LLM_KEY" ]; then
    echo -e "${COLOR_YELLOW}[!] WARNING: CYNUX_LLM__ANTHROPIC_API_KEY is not set in .env.${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}    The agent worker requires an LLM API key to perform security scans.${COLOR_RESET}"
fi

# 5. Determine deployment mode
TUNNEL_MODE=false
PROD_MODE=false

for arg in "$@"; do
    case $arg in
        --tunnel) TUNNEL_MODE=true ;;
        --prod) PROD_MODE=true ;;
    esac
done

# 6. Bring up DefectDojo vulnerability management stack
echo -e "${COLOR_GREEN}[+] Starting DefectDojo vulnerability store...${COLOR_RESET}"
docker compose --profile defectdojo up -d defectdojo-postgres defectdojo-redis defectdojo-initializer defectdojo-uwsgi defectdojo-nginx

echo -e "${COLOR_CYAN}[+] Waiting for DefectDojo initialization...${COLOR_RESET}"
until [ "$(docker inspect -f '{{.State.Status}}' cynux-defectdojo-initializer-1 2>/dev/null)" == "exited" ] || \
      [ "$(docker inspect -f '{{.State.Status}}' cyber-ai-defectdojo-initializer-1 2>/dev/null)" == "exited" ]; do
    sleep 3
done

# 7. Mint DefectDojo token into .env
echo -e "${COLOR_GREEN}[+] Minting DefectDojo API token...${COLOR_RESET}"
if command -v python3 &> /dev/null; then
    python3 docker/defectdojo-token.py || true
else
    python docker/defectdojo-token.py || true
fi

# 8. Spin up full Cynux application stack
if [ "$PROD_MODE" = true ]; then
    echo -e "${COLOR_GREEN}[+] Launching Production Stack with Caddy Auto-HTTPS...${COLOR_RESET}"
    docker compose -f docker-compose.prod.yml --profile defectdojo up -d --build
elif [ "$TUNNEL_MODE" = true ]; then
    echo -e "${COLOR_GREEN}[+] Launching Stack with Cloudflare Tunnel Public HTTPS...${COLOR_RESET}"
    docker compose --profile defectdojo -f docker-compose.yml -f docker-compose.tunnel.yml up -d --build
    echo -e "${COLOR_CYAN}[+] Waiting for Cloudflare Tunnel URL...${COLOR_RESET}"
    sleep 5
    docker compose logs cloudflared | grep -o 'https://.*\.trycloudflare\.com' | tail -n 1 || true
else
    echo -e "${COLOR_GREEN}[+] Launching Standard Docker Stack...${COLOR_RESET}"
    docker compose --profile defectdojo up -d --build
fi

echo -e "${COLOR_GREEN}====================================================${COLOR_RESET}"
echo -e "${COLOR_GREEN}    Cynux Deployment Completed Successfully!        ${COLOR_RESET}"
echo -e "${COLOR_GREEN}====================================================${COLOR_RESET}"
echo -e "Frontend Web App:  http://localhost:3000"
echo -e "API Endpoints:     http://localhost:8000/docs"
echo -e "MinIO S3 Console:  http://localhost:9001"
echo -e "DefectDojo Store:  http://localhost:8080"
