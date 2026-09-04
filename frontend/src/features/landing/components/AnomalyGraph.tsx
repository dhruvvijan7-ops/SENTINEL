import { useRef } from "react";
import { motion, useInView } from "framer-motion";

export default function AnomalyGraph() {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-80px" });

  const normalPath =
    "M 0 80 Q 40 78 80 75 Q 120 72 160 74 Q 200 76 240 73 Q 280 70 320 72 Q 360 74 400 71 Q 440 68 480 70 Q 520 72 560 69 Q 600 66 640 68 Q 680 70 720 67 Q 760 64 800 66";

  const anomalyPath =
    "M 560 69 Q 580 60 600 40 Q 620 20 640 8 Q 660 2 680 30 Q 700 55 720 67";

  return (
    <section id="technology" className="relative py-32 px-6">
      <div className="mx-auto max-w-5xl">
        <div className="text-center mb-16">
          <p className="mb-4 text-xs font-semibold tracking-[0.2em] text-[#FF3B30]">AI DETECTION</p>
          <h2 className="text-3xl font-bold text-white md:text-4xl">
            Anomalies can&apos;t hide from ML
          </h2>
          <p className="mt-4 text-[#A3A3A3] max-w-xl mx-auto">
            SentinelAI learns your network&apos;s normal behaviour and identifies deviations that indicate threats.
          </p>
        </div>

        <div
          ref={ref}
          className="relative rounded-2xl border border-[#242424] bg-[#0D0D0D] p-6 md:p-10"
        >
          {/* Labels */}
          <div className="mb-6 flex items-center justify-between">
            <span className="text-[11px] font-semibold tracking-wider text-[#737373]">NETWORK TRAFFIC ANALYSIS</span>
            <div className="flex items-center gap-4">
              <span className="flex items-center gap-1.5 text-[10px] text-[#737373]">
                <span className="size-1.5 rounded-full bg-[#3B9EFF]" /> Normal
              </span>
              <span className="flex items-center gap-1.5 text-[10px] text-[#737373]">
                <span className="size-1.5 rounded-full bg-[#FF7A00]" /> Anomaly
              </span>
              <span className="flex items-center gap-1.5 text-[10px] text-[#737373]">
                <span className="size-1.5 rounded-full bg-[#FF3B30]" /> Critical
              </span>
            </div>
          </div>

          <svg viewBox="0 0 800 120" className="w-full" preserveAspectRatio="none">
            {/* Baseline */}
            <line x1="0" y1="70" x2="800" y2="70" stroke="#242424" strokeWidth="1" strokeDasharray="4 4" />

            {/* Normal traffic */}
            <motion.path
              d={normalPath}
              fill="none"
              stroke="#3B9EFF"
              strokeWidth="2"
              initial={{ pathLength: 0 }}
              animate={inView ? { pathLength: 1 } : {}}
              transition={{ duration: 2, ease: "easeOut" }}
            />

            {/* Anomaly spike */}
            <motion.path
              d={anomalyPath}
              fill="none"
              stroke="#FF7A00"
              strokeWidth="2.5"
              initial={{ pathLength: 0 }}
              animate={inView ? { pathLength: 1 } : {}}
              transition={{ duration: 1, delay: 1.5, ease: "easeOut" }}
            />

            {/* Anomaly marker */}
            <motion.g
              initial={{ opacity: 0, scale: 0 }}
              animate={inView ? { opacity: 1, scale: 1 } : {}}
              transition={{ duration: 0.4, delay: 2.5 }}
            >
              <circle cx="640" cy="8" r="6" fill="#FF3B30" />
              <circle cx="640" cy="8" r="12" fill="#FF3B30" opacity="0.15">
                <animate attributeName="r" from="6" to="16" dur="2s" repeatCount="indefinite" />
                <animate attributeName="opacity" from="0.2" to="0" dur="2s" repeatCount="indefinite" />
              </circle>
            </motion.g>

            {/* Annotation */}
            <motion.g
              initial={{ opacity: 0 }}
              animate={inView ? { opacity: 1 } : {}}
              transition={{ duration: 0.5, delay: 2.8 }}
            >
              <line x1="640" y1="8" x2="640" y2="-10" stroke="#FF3B30" strokeWidth="1" strokeDasharray="2 2" />
              <text x="640" y="-16" textAnchor="middle" fill="#FF3B30" fontSize="10" fontWeight="600">
                ANOMALY
              </text>
            </motion.g>
          </svg>

          {/* Baseline label */}
          <div className="mt-4 flex items-center justify-between text-[10px] text-[#737373]">
            <span>t = 0</span>
            <span>Normal baseline ───────────────</span>
            <span>t = now</span>
          </div>
        </div>
      </div>
    </section>
  );
}
