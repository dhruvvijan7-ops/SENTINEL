import { motion } from "framer-motion";
import { Activity, AlertTriangle, Shield, Wifi } from "lucide-react";

const events = [
  { type: "normal", label: "Normal traffic", color: "#22C55E" },
  { type: "normal", label: "DNS resolution", color: "#22C55E" },
  { type: "suspicious", label: "Suspicious connection from 192.168.1.45", color: "#FF7A00" },
  { type: "normal", label: "TLS handshake completed", color: "#22C55E" },
  { type: "critical", label: "Anomaly detected — port scan pattern", color: "#FF3B30" },
  { type: "normal", label: "Packet capture streaming", color: "#22C55E" },
];

const container = {
  hidden: {},
  show: { transition: { staggerChildren: 0.08, delayChildren: 0.3 } },
};

const item = {
  hidden: { opacity: 0, y: 12 },
  show: { opacity: 1, y: 0, transition: { duration: 0.4, ease: [0.22, 1, 0.36, 1] as const } },
};

function MiniGraph() {
  const points = "0,40 30,38 60,35 90,37 120,30 150,28 180,32 210,20 240,18 270,22 300,15 330,35 360,12 390,10";

  return (
    <svg viewBox="0 0 390 50" className="w-full" preserveAspectRatio="none">
      <defs>
        <linearGradient id="graphGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#3B9EFF" stopOpacity="0.2" />
          <stop offset="100%" stopColor="#3B9EFF" stopOpacity="0" />
        </linearGradient>
      </defs>
      <polygon points={`0,50 ${points} 390,50`} fill="url(#graphGrad)" />
      <polyline points={points} fill="none" stroke="#3B9EFF" strokeWidth="1.5" />
      <circle cx="360" cy="12" r="4" fill="#FF3B30" />
      <circle cx="360" cy="12" r="8" fill="#FF3B30" opacity="0.2">
        <animate attributeName="r" from="4" to="12" dur="2s" repeatCount="indefinite" />
        <animate attributeName="opacity" from="0.3" to="0" dur="2s" repeatCount="indefinite" />
      </circle>
    </svg>
  );
}

export default function DashboardMockup() {
  return (
    <motion.div
      variants={container}
      initial="hidden"
      animate="show"
      className="relative w-full max-w-3xl mx-auto"
    >
      {/* Outer frame */}
      <motion.div
        variants={item}
        className="rounded-2xl border border-[#242424] bg-[#0D0D0D] shadow-2xl shadow-black/50 overflow-hidden"
      >
        {/* Title bar */}
        <div className="flex items-center gap-2 border-b border-[#242424] px-4 py-3">
          <div className="flex gap-1.5">
            <span className="size-2.5 rounded-full bg-[#FF3B30]" />
            <span className="size-2.5 rounded-full bg-[#F5C542]" />
            <span className="size-2.5 rounded-full bg-[#22C55E]" />
          </div>
          <span className="ml-3 text-[11px] font-medium text-[#737373]">Sentinel — Network Monitor</span>
        </div>

        {/* Stats row */}
        <motion.div variants={item} className="grid grid-cols-2 md:grid-cols-4 gap-px bg-[#242424]">
          {[
            { icon: Wifi, label: "PACKETS/S", value: "12,482", color: "#3B9EFF" },
            { icon: Activity, label: "MONITORING", value: "LIVE", color: "#22C55E" },
            { icon: AlertTriangle, label: "ANOMALIES", value: "13", color: "#FF7A00" },
            { icon: Shield, label: "CRITICAL", value: "3", color: "#FF3B30" },
          ].map((stat) => (
            <div key={stat.label} className="bg-[#0D0D0D] p-4">
              <div className="flex items-center gap-1.5">
                <stat.icon className="size-3" style={{ color: stat.color }} />
                <span className="text-[10px] font-semibold tracking-wider text-[#737373]">{stat.label}</span>
              </div>
              <p className="mt-2 text-xl font-bold text-white">{stat.value}</p>
            </div>
          ))}
        </motion.div>

        {/* Network graph */}
        <motion.div variants={item} className="border-t border-[#242424] p-4">
          <div className="flex items-center justify-between mb-3">
            <span className="text-[11px] font-semibold text-[#737373]">NETWORK TRAFFIC</span>
            <span className="text-[10px] text-[#737373]">Last 60s</span>
          </div>
          <MiniGraph />
        </motion.div>

        {/* Event log */}
        <motion.div variants={item} className="border-t border-[#242424]">
          <div className="px-4 py-2.5">
            <span className="text-[11px] font-semibold text-[#737373]">LIVE EVENTS</span>
          </div>
          <div className="divide-y divide-[#242424]">
            {events.map((ev, i) => (
              <motion.div
                key={i}
                variants={item}
                className="flex items-center gap-3 px-4 py-2.5 transition-colors hover:bg-[#141414]"
              >
                <span className="size-1.5 shrink-0 rounded-full" style={{ backgroundColor: ev.color }} />
                <span className="truncate text-[12px] text-[#D0D0D0]">{ev.label}</span>
                <span className="ml-auto shrink-0 text-[10px] text-[#737373]">
                  {`${Math.floor(Math.random() * 59) + 1}s ago`}
                </span>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </motion.div>
    </motion.div>
  );
}
