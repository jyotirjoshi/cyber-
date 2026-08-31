/**
 * Next.js config. `output: "standalone"` is REQUIRED by docker/frontend.Dockerfile,
 * which copies .next/standalone and runs `node server.js`.
 *
 * NEXT_PUBLIC_API_BASE_URL and NEXT_PUBLIC_WS_BASE_URL are inlined into the client
 * bundle at build time (they arrive as Docker build args from .env).
 */
/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  reactStrictMode: true,
  // Lint is a dev-time concern; never let a style rule break the production image.
  // Type errors still fail the build.
  eslint: { ignoreDuringBuilds: true },
};

export default nextConfig;
