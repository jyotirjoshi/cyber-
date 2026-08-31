# Cynux — 24/7 Free Cloud Hosting Guide (PC Off Setup)

This guide shows you how to host both the **Frontend** and **Backend** 100% in the cloud for **FREE**, so your application runs 24/7 even when your PC is turned off!

---

## 24/7 Free Cloud Hosting Architecture

```
┌─────────────────────────┐        ┌─────────────────────────┐
│     Vercel (Free)       │        │  Render / Koyeb (Free)  │
│                         │ HTTP / │                         │
│  Next.js Frontend UI    │───────►│  FastAPI Backend API    │
│  cynux-app.vercel.app   │  WSS   │  cynux-api.onrender.com │
└─────────────────────────┘        └─────────────────────────┘
```

---

## Option 1: Render.com (100% Free - 24/7 Cloud Service)

Render hosts your backend API and PostgreSQL database 24/7 in the cloud. No local PC required.

### Steps:
1. Push your repository to GitHub:
   ```bash
   git add .
   git commit -m "Deploy 24/7 cloud backend"
   git push origin main
   ```
2. Log into [Render Dashboard](https://dashboard.render.com/) (Free account).
3. Click **New +** $\rightarrow$ **Blueprint**.
4. Connect your GitHub repository. Render automatically reads [render.yaml](file:///c:/Users/spars/OneDrive/Desktop/cyber-ai/render.yaml) to set up the backend and database.
5. In Environment Variables, paste your `CYNUX_LLM__ANTHROPIC_API_KEY` (`sk-ant-...`).
6. Click **Apply**. Render will deploy your backend 24/7 at `https://cynux-api.onrender.com`.

---

## Option 2: Oracle Cloud Always Free VM (100% Free Forever - Full Docker Support)

Oracle Cloud gives you an **Always Free Cloud VPS** with 4 vCPUs, 24 GB RAM, and 200 GB SSD storage. It runs 24/7 in the cloud permanently.

### Steps:
1. Create a free account at [Oracle Cloud Free Tier](https://www.oracle.com/cloud/free/).
2. Create an **Ubuntu Ampere VM** (Select Always Free shape: 4 vCPU, 24 GB RAM).
3. SSH into your Oracle Cloud VM and run:
   ```bash
   git clone https://github.com/your-username/cyber-ai.git
   cd cyber-ai
   bash deploy.sh --prod
   ```
4. Your application runs 24/7 on the cloud server.

---

## Option 3: Koyeb Free Cloud Platform (100% Free - 24/7 Cloud)

1. Log into [Koyeb Dashboard](https://app.koyeb.com/) (Free account).
2. Click **Create Service** $\rightarrow$ **GitHub**.
3. Select `cyber-ai` repository and use `docker/backend.Dockerfile`.
4. Set port to `8000` and deploy.

---


## Part 1: Host the Backend on Render (100% Free)

Render provides a Free Tier for web services, PostgreSQL, and Redis.

### Steps:
1. **Push your code to GitHub / GitLab**.
2. Go to [Render Dashboard](https://dashboard.render.com/) and sign up / log in.
3. Click **New +** -> **Blueprint**.
4. Connect your `cyber-ai` repository.
5. Render will automatically detect [render.yaml](file:///c:/Users/spars/OneDrive/Desktop/cyber-ai/render.yaml) and prompt you to create:
   - `cynux-api` (FastAPI Web Service)
   - `cynux-db` (PostgreSQL Database)
6. Under Environment Variables for `cynux-api`, enter your `CYNUX_LLM__ANTHROPIC_API_KEY` (e.g. `sk-ant-...`).
7. Click **Apply**.
8. Once deployed, copy your Render API URL (e.g., `https://cynux-api.onrender.com`).

---

## Part 2: Host the Frontend on Vercel (100% Free)

Vercel provides a Free Hobby tier for Next.js web applications.

### Steps:
1. Open your terminal in `frontend/` directory or go to [Vercel Dashboard](https://vercel.com/new).
2. Connect your `cyber-ai` repository and select the `frontend` root directory.
3. Configure Environment Variables in Vercel:
   - `NEXT_PUBLIC_API_BASE_URL` = `https://cynux-api.onrender.com` (Your Render API URL)
   - `NEXT_PUBLIC_WS_BASE_URL` = `wss://cynux-api.onrender.com`
4. Click **Deploy**.
5. Your frontend will be live on `https://cynux-frontend.vercel.app`!

---


## Deployment Options at a Glance

| Deployment Target | Hosting Strategy | SSL/TLS | Setup Complexity | Best For |
|---|---|---|---|---|
| **Option 1: Instant Cloudflare Tunnel** | Local host / VPS + `cloudflared` | Automatic Cloudflare HTTPS | Zero config (1 command) | Quick testing, demos, zero server costs |
| **Option 2: Production Cloud VPS** | AWS / DigitalOcean / Hetzner / Linode / GCP + Caddy | Automatic Let's Encrypt | Low (`deploy.sh --prod`) | Full production self-hosting with custom domain |
| **Option 3: Container PaaS** | Coolify / CapRover / Render / Railway | Automatic PaaS HTTPS | Medium | Managed container deployment |
| **Option 4: Split Deployment** | Vercel (Frontend) + VPS (Backend) | Automatic Vercel & Caddy HTTPS | Medium | Edge frontend performance |

---

## Prerequisites

1. **Docker** with **Compose v2** plugin installed on the host.
2. **LLM Provider API Key** (Anthropic Claude, OpenAI, or Google Gemini).
3. ~4 GB RAM available on the host machine.

---

## Option 1: Instant Cloudflare Tunnel (Free & Fast)

Expose your locally running or VPS-hosted Cynux platform instantly to a secure public `https://*.trycloudflare.com` URL with WebSockets and SSL enabled.

### Steps:

1. Clone the repository and navigate to the project directory:
   ```bash
   cd cyber-ai
   ```

2. Run the deployment script with `--tunnel`:
   - **Linux / macOS**:
     ```bash
     bash deploy.sh --tunnel
     ```
   - **Windows (PowerShell)**:
     ```powershell
     .\deploy.ps1 -Tunnel
     ```

3. Open the output logs to retrieve your instant public URL:
   ```bash
   docker compose logs cloudflared | grep trycloudflare.com
   ```

---

## Option 2: Production Cloud VPS (AWS, DigitalOcean, Hetzner, Linode, GCP)

Deploy the entire stack with automatic SSL/TLS certificates generated via Caddy reverse proxy for your custom domain.

### Steps:

1. **DNS Setup**: Point your domain `A` record (e.g., `cynux.yourdomain.com`) to your VPS IP address.

2. **Configure `.env`**:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and set:
   ```env
   DOMAIN_NAME=cynux.yourdomain.com
   LETSENCRYPT_EMAIL=your-email@example.com
   CYNUX_ENVIRONMENT=production
   CYNUX_PUBLIC_BASE_URL=https://cynux.yourdomain.com
   CYNUX_CORS_ORIGINS=https://cynux.yourdomain.com
   CYNUX_LLM__ANTHROPIC_API_KEY=sk-ant-...
   ```

3. **Deploy**:
   ```bash
   bash deploy.sh --prod
   ```
   Or manually:
   ```bash
   python docker/gen-secrets.py
   docker compose -f docker-compose.prod.yml --profile defectdojo up -d --build
   python docker/defectdojo-token.py
   ```

4. Access your application at `https://cynux.yourdomain.com`.

---

## Option 3: Container PaaS (Coolify / CapRover)

### Using Coolify or CapRover:

1. Connect your Git repository to Coolify / CapRover.
2. Select **Docker Compose** build type.
3. Set the Compose file path to `docker-compose.prod.yml`.
4. Supply environment variables from `.env.example` in your PaaS dashboard.
5. Deploy the application stack.

---

## Option 4: Split Deployment (Vercel Frontend + Docker Backend)

If you prefer hosting the Next.js UI on Vercel:

1. **Deploy Backend**: Deploy the Cynux backend services on a Docker host (VPS / Railway / Render) following Option 2.
2. **Deploy Frontend on Vercel**:
   - Push repository to GitHub/GitLab.
   - Import the `frontend/` directory into Vercel.
   - Set Environment Variables on Vercel:
     - `NEXT_PUBLIC_API_BASE_URL=https://api.yourdomain.com`
     - `NEXT_PUBLIC_WS_BASE_URL=wss://api.yourdomain.com`
   - Click **Deploy**.

---

## Verification & Health Check Commands

Check platform health at any time:

```bash
# Verify stack status
docker compose ps

# Check API health
curl http://localhost:8000/healthz
curl http://localhost:8000/readyz

# Tail logs
docker compose logs -f
```

---

## Troubleshooting

- **Worker restarting**: Verify `CYNUX_LLM__ANTHROPIC_API_KEY` is non-empty in `.env` and DefectDojo API token is generated (`make defectdojo-token` or `python docker/defectdojo-token.py`).
- **DefectDojo unreachable**: Wait ~1-2 minutes on first boot for `defectdojo-initializer` to complete database migrations.
- **Port clashes**: Adjust port mappings (`CYNUX_FRONTEND_PORT`, `CYNUX_API_PORT`, `DEFECTDOJO_PORT`) in `.env`.
