import Link from "next/link";
import { PUBLIC_CAPABILITIES } from "../lib/landing-capabilities";

const workflow = [
  { number: "01", title: "Scope", description: "Define authorized targets and assessment depth before any active scan runs." },
  { number: "02", title: "Discover", description: "Bring scanner output and connected security alerts into your organization's workspace." },
  { number: "03", title: "Prioritize", description: "Add CVE, KEV, EPSS, asset criticality and analyst context to the findings that matter." },
  { number: "04", title: "Act", description: "Review AI guidance, record validation evidence, create Jira work and track progress." },
] as const;

export default function LandingPage() {
  return (
    <main className="min-h-screen bg-[#07110e] text-[#eef8f2]">
      <div className="pointer-events-none absolute inset-x-0 top-0 h-[600px] bg-[radial-gradient(ellipse_at_70%_0%,rgba(25,125,80,0.22),transparent_60%)]" />
      <div className="relative mx-auto max-w-7xl px-6 lg:px-10">
        <header className="flex items-center justify-between border-b border-emerald-300/15 py-6">
          <Link href="/" className="text-xl font-bold tracking-tight text-white" aria-label="Cynux home">cynux<span className="text-emerald-400">.</span></Link>
          <nav className="flex items-center gap-4 text-sm">
            <a href="#platform" className="hidden text-emerald-100/75 hover:text-white sm:inline">Platform</a>
            <a href="/login" className="text-emerald-100/75 hover:text-white">Sign in</a>
            <a href="/register" className="rounded-lg bg-emerald-400 px-4 py-2 font-semibold text-[#062115] hover:bg-emerald-300">Get started</a>
          </nav>
        </header>

        <section className="grid gap-14 py-24 lg:grid-cols-[1.2fr_0.8fr] lg:items-center lg:py-36">
          <div>
            <p className="mb-6 inline-flex rounded-full border border-emerald-400/25 bg-emerald-400/10 px-4 py-1.5 text-xs font-semibold uppercase tracking-[0.2em] text-emerald-300">Security work, connected</p>
            <h1 className="max-w-3xl text-5xl font-semibold leading-[1.06] tracking-tight text-white sm:text-7xl">Find the exposure. Keep the evidence. Move the fix forward.</h1>
            <p className="mt-7 max-w-2xl text-lg leading-8 text-emerald-100/70">Cynux brings approved assessments, connected security alerts and risk context into one workspace. Your team stays in control of scans, AI provider keys and outbound actions.</p>
            <div className="mt-9 flex flex-wrap gap-3">
              <a href="/register" className="rounded-xl bg-emerald-400 px-6 py-3 font-semibold text-[#062115] hover:bg-emerald-300">Create an organization</a>
              <a href="/login" className="rounded-xl border border-emerald-200/25 px-6 py-3 font-semibold text-white hover:border-emerald-300/60">Open your workspace</a>
            </div>
          </div>
          <div className="rounded-3xl border border-emerald-300/20 bg-[#0d2118]/80 p-6 shadow-[0_30px_90px_rgba(0,0,0,0.25)] sm:p-8">
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-emerald-300">Your workflow</p>
            <div className="mt-7 space-y-5">
              {workflow.map((step) => (
                <div key={step.number} className="grid grid-cols-[44px_1fr] gap-4 border-b border-emerald-300/10 pb-5 last:border-0 last:pb-0">
                  <span className="font-mono text-sm text-emerald-400">{step.number}</span>
                  <div>
                    <h2 className="font-semibold text-white">{step.title}</h2>
                    <p className="mt-1 text-sm leading-6 text-emerald-100/60">{step.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section id="platform" className="border-t border-emerald-300/15 py-20">
          <div className="max-w-3xl">
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-emerald-300">What is connected in code</p>
            <h2 className="mt-4 text-3xl font-semibold tracking-tight text-white sm:text-4xl">Built around tools security teams already use.</h2>
            <p className="mt-4 leading-7 text-emerald-100/65">Configure integrations with your organization&apos;s credentials. Scanner execution and third-party access depend on your deployment and provider permissions.</p>
          </div>
          <ul className="mt-9 flex flex-wrap gap-3" aria-label="Implemented tools and integrations">
            {PUBLIC_CAPABILITIES.map((name) => (
              <li key={name} className="rounded-full border border-emerald-300/20 bg-emerald-300/5 px-4 py-2 text-sm text-emerald-100">{name}</li>
            ))}
          </ul>
          <p className="mt-6 text-sm text-emerald-100/50">AI model choices: OpenAI, Anthropic, Google and OpenRouter, using your own provider keys.</p>
        </section>

        <footer className="flex flex-wrap items-center justify-between gap-3 border-t border-emerald-300/15 py-8 text-sm text-emerald-100/50">
          <span>Cynux · Exposure management with human control</span>
          <a href="/login" className="hover:text-white">Sign in to your workspace →</a>
        </footer>
      </div>
    </main>
  );
}
