import { useRef } from "react";
import { motion, useInView } from "framer-motion";
import { Link } from "react-router-dom";
import { ArrowRight } from "lucide-react";
import { ROUTES } from "@/routes/paths";

export default function CTASection() {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-80px" });

  return (
    <section className="relative py-32 px-6">
      <div ref={ref} className="mx-auto max-w-3xl text-center">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
        >
          <h2 className="text-3xl font-bold text-white md:text-5xl">
            Start monitoring your network
            <br />
            <span className="text-[#FF3B30]">in minutes</span>
          </h2>
          <p className="mt-6 text-lg text-[#A3A3A3] max-w-lg mx-auto">
            Deploy SentinelAI with Docker and start detecting threats on your first packet capture.
          </p>

          <div className="mt-10 flex flex-col items-center gap-4 sm:flex-row sm:justify-center">
            <Link
              to={ROUTES.register}
              className="group inline-flex items-center gap-2 rounded-xl bg-[#FF3B30] px-8 py-3.5 text-sm font-semibold text-white transition-all hover:bg-[#FF5147] active:scale-[0.97]"
            >
              Get Started Free
              <ArrowRight className="size-4 transition-transform group-hover:translate-x-0.5" />
            </Link>
            <Link
              to={ROUTES.login}
              className="inline-flex items-center gap-2 rounded-xl border border-[#333] bg-[#0D0D0D] px-8 py-3.5 text-sm font-semibold text-white transition-all hover:border-[#444] hover:bg-[#141414]"
            >
              View Documentation
            </Link>
          </div>

          {/* Trust signals */}
          <div className="mt-12 flex items-center justify-center gap-6 text-[11px] text-[#737373]">
            <span className="flex items-center gap-1.5">
              <span className="size-1.5 rounded-full bg-[#22C55E]" />
              Open Source Core
            </span>
            <span className="flex items-center gap-1.5">
              <span className="size-1.5 rounded-full bg-[#22C55E]" />
              Docker Ready
            </span>
            <span className="flex items-center gap-1.5">
              <span className="size-1.5 rounded-full bg-[#22C55E]" />
              PostgreSQL
            </span>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
