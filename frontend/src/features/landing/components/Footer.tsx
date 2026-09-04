import { Link } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { ROUTES } from "@/routes/paths";

const columns = [
  {
    title: "Product",
    links: [
      { label: "Features", href: "#features" },
      { label: "Architecture", href: "#architecture" },
      { label: "How It Works", href: "#how-it-works" },
      { label: "Technology", href: "#technology" },
    ],
  },
  {
    title: "Developers",
    links: [
      { label: "Documentation", href: "#" },
      { label: "API Reference", href: "#" },
      { label: "Deployment Guide", href: "#" },
    ],
  },
  {
    title: "Company",
    links: [
      { label: "About", href: "#" },
      { label: "Blog", href: "#" },
      { label: "GitHub", href: "#" },
    ],
  },
];

export default function Footer() {
  return (
    <footer className="border-t border-[#242424] bg-[#050505] py-16 px-6">
      <div className="mx-auto max-w-5xl">
        <div className="grid gap-10 sm:grid-cols-2 lg:grid-cols-4">
          {/* Brand */}
          <div>
            <Link to={ROUTES.dashboard} className="flex items-center gap-2.5">
              <div className="flex size-7 items-center justify-center rounded-lg bg-[#FF3B30]">
                <ShieldCheck className="size-3.5 text-white" />
              </div>
              <span className="text-xs font-bold tracking-wide text-white">SENTINEL</span>
            </Link>
            <p className="mt-4 text-[13px] leading-relaxed text-[#737373] max-w-xs">
              AI-powered network security monitoring platform. Detect threats in real time with ML-based anomaly detection.
            </p>
          </div>

          {/* Columns */}
          {columns.map((col) => (
            <div key={col.title}>
              <p className="mb-4 text-[11px] font-semibold tracking-[0.15em] text-[#A3A3A3]">{col.title.toUpperCase()}</p>
              <ul className="space-y-2.5">
                {col.links.map((link) => (
                  <li key={link.label}>
                    <a
                      href={link.href}
                      className="text-[13px] text-[#737373] transition-colors hover:text-white"
                    >
                      {link.label}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        {/* Bottom bar */}
        <div className="mt-14 flex flex-col items-center justify-between gap-4 border-t border-[#242424] pt-8 sm:flex-row">
          <p className="text-[11px] text-[#737373]">
            &copy; {new Date().getFullYear()} Sentinel. All rights reserved.
          </p>
          <div className="flex gap-6 text-[11px] text-[#737373]">
            <a href="#" className="transition-colors hover:text-white">Privacy</a>
            <a href="#" className="transition-colors hover:text-white">Terms</a>
            <a href="#" className="transition-colors hover:text-white">Security</a>
          </div>
        </div>
      </div>
    </footer>
  );
}
