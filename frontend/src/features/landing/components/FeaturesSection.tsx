import { Shield, Zap, Brain, Eye, Lock, Network } from "lucide-react";
import Reveal from "./Reveal";

const features = [
  {
    icon: Shield,
    title: "Real-Time Monitoring",
    desc: "Continuous network surveillance with live packet capture and flow analysis.",
    color: "#FF3B30",
  },
  {
    icon: Brain,
    title: "ML Anomaly Detection",
    desc: "Machine learning models trained on your network behaviour to surface threats.",
    color: "#3B9EFF",
  },
  {
    icon: Zap,
    title: "Instant Alerts",
    desc: "Priority-ranked security alerts delivered the moment a threat is detected.",
    color: "#F5C542",
  },
  {
    icon: Eye,
    title: "Threat Visibility",
    desc: "Full observability into host traces, connections, and packet distributions.",
    color: "#22C55E",
  },
  {
    icon: Lock,
    title: "Zero-Trust Ready",
    desc: "Authentication and access controls built into every layer of the platform.",
    color: "#FF7A00",
  },
  {
    icon: Network,
    title: "Protocol Support",
    desc: "Parse and analyze TCP, UDP, ICMP, HTTP, DNS, and TLS traffic patterns.",
    color: "#BF5AF2",
  },
];

export default function FeaturesSection() {
  return (
    <section className="relative py-32 px-6">
      <div className="mx-auto max-w-5xl">
        <div className="text-center mb-16">
          <p className="mb-4 text-xs font-semibold tracking-[0.2em] text-[#FF3B30]">CAPABILITIES</p>
          <h2 className="text-3xl font-bold text-white md:text-4xl">
            Built for security teams
          </h2>
          <p className="mt-4 text-[#A3A3A3] max-w-xl mx-auto">
            Everything you need to detect, investigate, and respond to network threats.
          </p>
        </div>

        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {features.map((f, i) => (
            <Reveal key={f.title} delay={i * 0.06}>
              <div className="group relative rounded-2xl border border-[#242424] bg-[#0D0D0D] p-6 transition-all duration-300 hover:border-[#333] hover:bg-[#141414]">
                <div
                  className="mb-4 flex size-10 items-center justify-center rounded-xl"
                  style={{ backgroundColor: `${f.color}15` }}
                >
                  <f.icon className="size-5" style={{ color: f.color }} />
                </div>
                <h3 className="mb-2 text-sm font-semibold text-white">{f.title}</h3>
                <p className="text-[13px] leading-relaxed text-[#A3A3A3]">{f.desc}</p>
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
