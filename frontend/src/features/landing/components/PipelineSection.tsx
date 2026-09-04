import { useRef } from "react";
import { motion, useInView } from "framer-motion";
import { Network, ScanSearch, Brain, Bell } from "lucide-react";

const steps = [
  { icon: Network, label: "Network Traffic", desc: "Raw packets and flow data" },
  { icon: ScanSearch, label: "Feature Extraction", desc: "Protocol analysis and normalization" },
  { icon: Brain, label: "ML Anomaly Detection", desc: "AI-powered threat classification" },
  { icon: Bell, label: "Security Alert", desc: "Prioritized threat notification" },
];

export default function PipelineSection() {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-100px" });

  return (
    <section id="how-it-works" className="relative py-32 px-6">
      <div className="mx-auto max-w-5xl">
        <div className="text-center mb-20">
          <p className="mb-4 text-xs font-semibold tracking-[0.2em] text-[#FF3B30]">HOW IT WORKS</p>
          <h2 className="text-3xl font-bold text-white md:text-4xl">
            From raw traffic to actionable intelligence
          </h2>
          <p className="mt-4 text-[#A3A3A3] max-w-xl mx-auto">
            SentinelAI captures network data, extracts meaningful features, runs ML-based anomaly detection, and surfaces security alerts in real time.
          </p>
        </div>

        <div ref={ref} className="relative flex flex-col items-center gap-0">
          {steps.map((step, i) => (
            <div key={step.label} className="flex flex-col items-center">
              {/* Node */}
              <motion.div
                initial={{ opacity: 0, scale: 0.8 }}
                animate={inView ? { opacity: 1, scale: 1 } : {}}
                transition={{ duration: 0.5, delay: i * 0.2, ease: [0.22, 1, 0.36, 1] }}
                className={`relative flex items-center gap-4 rounded-2xl border px-6 py-5 ${
                  i === steps.length - 1
                    ? "border-[#FF3B30]/40 bg-[#FF3B30]/[0.06]"
                    : "border-[#242424] bg-[#0D0D0D]"
                }`}
              >
                <div
                  className={`flex size-10 shrink-0 items-center justify-center rounded-xl ${
                    i === steps.length - 1
                      ? "bg-[#FF3B30]/15 text-[#FF3B30]"
                      : "bg-[#191919] text-[#A3A3A3]"
                  }`}
                >
                  <step.icon className="size-5" />
                </div>
                <div>
                  <p className="text-sm font-semibold text-white">{step.label}</p>
                  <p className="text-xs text-[#737373]">{step.desc}</p>
                </div>
              </motion.div>

              {/* Connector */}
              {i < steps.length - 1 && (
                <motion.div
                  initial={{ scaleY: 0 }}
                  animate={inView ? { scaleY: 1 } : {}}
                  transition={{ duration: 0.4, delay: i * 0.2 + 0.15, ease: [0.22, 1, 0.36, 1] }}
                  className="h-12 w-px origin-top"
                  style={{
                    background: `linear-gradient(to bottom, #242424, ${
                      i === steps.length - 2 ? "#FF3B3040" : "#242424"
                    })`,
                  }}
                />
              )}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
