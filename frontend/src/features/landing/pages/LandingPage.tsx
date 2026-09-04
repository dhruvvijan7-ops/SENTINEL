import HeroCanvas from "../components/HeroCanvas";
import Navbar from "../components/Navbar";
import DashboardMockup from "../components/DashboardMockup";
import Reveal from "../components/Reveal";
import PipelineSection from "../components/PipelineSection";
import AnomalyGraph from "../components/AnomalyGraph";
import FeaturesSection from "../components/FeaturesSection";
import CTASection from "../components/CTASection";
import Footer from "../components/Footer";
import { Link } from "react-router-dom";
import { ROUTES } from "@/routes/paths";
import {
  ArrowRight,
  Terminal,
  Database,
  Server,
  Cpu,
} from "lucide-react";

const stats = [
  { value: "<50ms", label: "Detection latency" },
  { value: "99.9%", label: "Uptime SLA" },
  { value: "10K+", label: "Packets/second" },
  { value: "Zero", label: "False negatives" },
];

const architectureItems = [
  {
    icon: Server,
    title: "FastAPI Backend",
    desc: "High-performance async Python API with JWT auth and rate limiting.",
  },
  {
    icon: Database,
    title: "PostgreSQL",
    desc: "Reliable relational storage for users, alerts, hosts, and packet data.",
  },
  {
    icon: Cpu,
    title: "Detection Engine",
    desc: "Rule-based and ML-powered anomaly detection running in real time.",
  },
  {
    icon: Terminal,
    title: "Docker Deployment",
    desc: "Single `docker compose up` to run the entire platform locally.",
  },
];

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-black">
      <Navbar />

      {/* ======================== HERO ======================== */}
      <section className="relative flex min-h-screen flex-col items-center justify-center overflow-hidden px-6 pt-20">
        <HeroCanvas />

        {/* Grid overlay */}
        <div className="pointer-events-none absolute inset-0 sentinel-grid opacity-40" />

        <div className="relative z-10 mx-auto max-w-4xl text-center">
          {/* Badge */}
          <Reveal>
            <div className="mb-8 inline-flex items-center gap-2 rounded-full border border-[#242424] bg-[#0D0D0D] px-4 py-1.5">
              <span className="size-1.5 animate-pulse rounded-full bg-[#FF3B30]" />
              <span className="text-[11px] font-medium text-[#A3A3A3]">v1.0 — Now Available</span>
            </div>
          </Reveal>

          <Reveal delay={0.1}>
            <h1 className="text-4xl font-bold leading-[1.1] tracking-tight text-white md:text-6xl lg:text-7xl">
              AI-Powered Network
              <br />
              <span className="bg-gradient-to-r from-[#FF3B30] to-[#FF7A00] bg-clip-text text-transparent">
                Security Monitoring
              </span>
            </h1>
          </Reveal>

          <Reveal delay={0.2}>
            <p className="mx-auto mt-6 max-w-xl text-lg leading-relaxed text-[#A3A3A3]">
              Detect threats in real time with ML-based anomaly detection. From raw packets to actionable intelligence — Sentinel watches your network so you don&apos;t have to.
            </p>
          </Reveal>

          <Reveal delay={0.3}>
            <div className="mt-10 flex flex-col items-center gap-4 sm:flex-row sm:justify-center">
              <Link
                to={ROUTES.register}
                className="group inline-flex items-center gap-2 rounded-xl bg-[#FF3B30] px-8 py-3.5 text-sm font-semibold text-white transition-all hover:bg-[#FF5147] active:scale-[0.97]"
              >
                Start Monitoring
                <ArrowRight className="size-4 transition-transform group-hover:translate-x-0.5" />
              </Link>
              <Link
                to={ROUTES.login}
                className="inline-flex items-center gap-2 rounded-xl border border-[#333] bg-[#0D0D0D] px-8 py-3.5 text-sm font-semibold text-white transition-all hover:border-[#444] hover:bg-[#141414]"
              >
                Live Demo
              </Link>
            </div>
          </Reveal>

          <Reveal delay={0.4}>
            <div className="mt-16">
              <DashboardMockup />
            </div>
          </Reveal>
        </div>
      </section>

      {/* ======================== STATS BAR ======================== */}
      <section className="border-y border-[#242424] bg-[#050505]">
        <div className="mx-auto grid max-w-5xl grid-cols-2 md:grid-cols-4">
          {stats.map((s, i) => (
            <Reveal key={s.label} delay={i * 0.08}>
              <div className="flex flex-col items-center border-r border-[#242424] py-10 last:border-r-0">
                <span className="text-2xl font-bold text-white md:text-3xl">{s.value}</span>
                <span className="mt-1 text-[12px] text-[#737373]">{s.label}</span>
              </div>
            </Reveal>
          ))}
        </div>
      </section>

      {/* ======================== PRODUCT ======================== */}
      <section id="product" className="relative py-32 px-6">
        <div className="mx-auto max-w-5xl">
          <Reveal>
            <div className="text-center mb-16">
              <p className="mb-4 text-xs font-semibold tracking-[0.2em] text-[#FF3B30]">THE PROBLEM</p>
              <h2 className="text-3xl font-bold text-white md:text-4xl">
                Most teams find out too late
              </h2>
              <p className="mt-4 text-[#A3A3A3] max-w-xl mx-auto">
                Traditional security tools generate noise, miss novel attacks, and require constant tuning. SentinelAI takes a different approach.
              </p>
            </div>
          </Reveal>

          <div className="grid gap-6 md:grid-cols-2">
            {[
              {
                title: "Without Sentinel",
                items: ["Alert fatigue from thousands of false positives", "Manual rule tuning that never keeps up", "Blind spots in encrypted traffic", "Hours to investigate a single incident"],
                highlight: false,
              },
              {
                title: "With Sentinel",
                items: ["ML models that learn your network baseline", "Automated threat classification and prioritization", "Full visibility from packets to alerts", "Real-time detection in under 50ms"],
                highlight: true,
              },
            ].map((col) => (
              <Reveal key={col.title} delay={col.highlight ? 0.1 : 0}>
                <div
                  className={`rounded-2xl border p-8 ${
                    col.highlight
                      ? "border-[#FF3B30]/30 bg-[#FF3B30]/[0.04]"
                      : "border-[#242424] bg-[#0D0D0D]"
                  }`}
                >
                  <h3 className="mb-6 text-sm font-semibold text-white">{col.title}</h3>
                  <ul className="space-y-4">
                    {col.items.map((item) => (
                      <li key={item} className="flex items-start gap-3 text-[13px] text-[#A3A3A3]">
                        <span
                          className={`mt-1 size-1.5 shrink-0 rounded-full ${
                            col.highlight ? "bg-[#FF3B30]" : "bg-[#333]"
                          }`}
                        />
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* ======================== HOW IT WORKS ======================== */}
      <PipelineSection />

      {/* ======================== ARCHITECTURE ======================== */}
      <section id="architecture" className="relative py-32 px-6 border-t border-[#242424]">
        <div className="mx-auto max-w-5xl">
          <Reveal>
            <div className="text-center mb-16">
              <p className="mb-4 text-xs font-semibold tracking-[0.2em] text-[#FF3B30]">ARCHITECTURE</p>
              <h2 className="text-3xl font-bold text-white md:text-4xl">
                Built on a modern stack
              </h2>
              <p className="mt-4 text-[#A3A3A3] max-w-xl mx-auto">
                Every component is designed for performance, reliability, and developer experience.
              </p>
            </div>
          </Reveal>

          <div className="grid gap-4 sm:grid-cols-2">
            {architectureItems.map((item, i) => (
              <Reveal key={item.title} delay={i * 0.08}>
                <div className="flex gap-4 rounded-2xl border border-[#242424] bg-[#0D0D0D] p-6">
                  <div className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-[#191919] text-[#FF3B30]">
                    <item.icon className="size-5" />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-white">{item.title}</h3>
                    <p className="mt-1 text-[13px] text-[#A3A3A3]">{item.desc}</p>
                  </div>
                </div>
              </Reveal>
            ))}
          </div>

          {/* Code snippet */}
          <Reveal delay={0.3}>
            <div className="mt-10 rounded-2xl border border-[#242424] bg-[#0D0D0D] p-6">
              <div className="flex items-center gap-2 mb-4">
                <span className="size-2.5 rounded-full bg-[#FF3B30]" />
                <span className="size-2.5 rounded-full bg-[#F5C542]" />
                <span className="size-2.5 rounded-full bg-[#22C55E]" />
                <span className="ml-3 text-[11px] text-[#737373]">terminal</span>
              </div>
              <pre className="font-mono text-[13px] leading-relaxed text-[#A3A3A3] overflow-x-auto">
                <code>
                  <span className="text-[#737373]">$</span> docker compose up -d
                  {"\n"}
                  <span className="text-[#737373]">$</span> curl localhost:8000/api/system/status
                  {"\n"}
                  {`{"status":"healthy","database":"connected","version":"1.0.0"}`}
                </code>
              </pre>
            </div>
          </Reveal>
        </div>
      </section>

      {/* ======================== ANOMALY DETECTION ======================== */}
      <AnomalyGraph />

      {/* ======================== FEATURES ======================== */}
      <div id="features">
        <FeaturesSection />
      </div>

      {/* ======================== CTA ======================== */}
      <div className="border-t border-[#242424]">
        <CTASection />
      </div>

      {/* ======================== FOOTER ======================== */}
      <Footer />
    </div>
  );
}
