import { useState, useRef, useEffect } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { ShieldCheck } from "lucide-react";
import { ROUTES } from "@/routes/paths";

const navLinks = [
  { label: "Product", href: "#product" },
  { label: "How It Works", href: "#how-it-works" },
  { label: "Architecture", href: "#architecture" },
  { label: "Technology", href: "#technology" },
];

export default function Navbar() {
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);
  const [pillStyle, setPillStyle] = useState({ left: 0, width: 0, opacity: 0 });
  const containerRef = useRef<HTMLDivElement>(null);
  const itemRefs = useRef<(HTMLAnchorElement | null)[]>([]);

  useEffect(() => {
    if (hoveredIdx !== null && itemRefs.current[hoveredIdx] && containerRef.current) {
      const item = itemRefs.current[hoveredIdx];
      const container = containerRef.current;
      const itemRect = item.getBoundingClientRect();
      const containerRect = container.getBoundingClientRect();
      setPillStyle({
        left: itemRect.left - containerRect.left,
        width: itemRect.width,
        opacity: 1,
      });
    } else {
      setPillStyle((prev) => ({ ...prev, opacity: 0 }));
    }
  }, [hoveredIdx]);

  return (
    <nav className="fixed top-0 z-50 w-full border-b border-[#242424] bg-black/80 backdrop-blur-xl">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-6">
        {/* Logo */}
        <Link to={ROUTES.dashboard} className="flex items-center gap-2.5">
          <div className="flex size-8 items-center justify-center rounded-lg bg-[#FF3B30]">
            <ShieldCheck className="size-4 text-white" />
          </div>
          <span className="text-sm font-bold tracking-wide text-white">SENTINEL</span>
        </Link>

        {/* Nav links with pill */}
        <div
          ref={containerRef}
          className="relative hidden items-center gap-1 md:flex"
          onMouseLeave={() => setHoveredIdx(null)}
        >
          <motion.div
            className="absolute h-8 rounded-lg bg-white/[0.06]"
            animate={{ left: pillStyle.left, width: pillStyle.width, opacity: pillStyle.opacity }}
            transition={{ type: "spring", stiffness: 400, damping: 30 }}
          />
          {navLinks.map((link, i) => (
            <a
              key={link.href}
              ref={(el) => { itemRefs.current[i] = el; }}
              href={link.href}
              className="relative z-10 px-3.5 py-2 text-[13px] font-medium text-[#A3A3A3] transition-colors hover:text-white"
              onMouseEnter={() => setHoveredIdx(i)}
            >
              {link.label}
            </a>
          ))}
        </div>

        {/* Right side */}
        <div className="flex items-center gap-3">
          <Link
            to={ROUTES.login}
            className="hidden text-[13px] font-medium text-[#A3A3A3] transition-colors hover:text-white sm:block"
          >
            Documentation
          </Link>
          <Link
            to={ROUTES.login}
            className="rounded-lg bg-[#FF3B30] px-4 py-2 text-[13px] font-semibold text-white transition-all hover:bg-[#FF5147] active:scale-[0.97]"
          >
            Get Started
          </Link>
        </div>
      </div>
    </nav>
  );
}
