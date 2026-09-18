import { Footer } from "@/components/strobes/Footer";
import { Header } from "@/components/strobes/Header";
import { Hero } from "@/components/strobes/Hero";
import { InteractiveSandbox } from "@/components/strobes/InteractiveSandbox";
import { LogosMarquee } from "@/components/strobes/LogosMarquee";
import { MetricsGrid } from "@/components/strobes/MetricsGrid";
import { PentestMockup } from "@/components/strobes/PentestMockup";
import { PlatformSection } from "@/components/strobes/PlatformSection";

export default function LandingPage() {
  return (
    <main className="min-h-screen bg-[#030603] text-white selection:bg-emerald-500/30 selection:text-emerald-200">
      <Header />
      <Hero />
      <PentestMockup />
      <LogosMarquee />
      <MetricsGrid />
      <PlatformSection />
      <InteractiveSandbox />
      <Footer />
    </main>
  );
}
