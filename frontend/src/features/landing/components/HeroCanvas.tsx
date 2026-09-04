import { useCallback, useEffect, useRef } from "react";

interface Blob {
  x: number;
  y: number;
  r: number;
  vx: number;
  vy: number;
  phase: number;
}

export default function HeroCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const blobsRef = useRef<Blob[]>([]);
  const rafRef = useRef<number>(0);
  const visibleRef = useRef(true);

  const init = useCallback((canvas: HTMLCanvasElement) => {
    const w = canvas.width;
    const h = canvas.height;
    blobsRef.current = Array.from({ length: 5 }, (_, i) => ({
      x: w * (0.2 + (i * 0.15)),
      y: h * (0.3 + Math.sin(i) * 0.2),
      r: 120 + i * 30,
      vx: (0.15 + i * 0.05) * (i % 2 === 0 ? 1 : -1),
      vy: (0.1 + i * 0.03) * (i % 3 === 0 ? 1 : -1),
      phase: i * 1.2,
    }));
  }, []);

  const draw = useCallback((canvas: HTMLCanvasElement, ctx: CanvasRenderingContext2D) => {
    const w = canvas.width;
    const h = canvas.height;
    const t = performance.now() * 0.001;

    ctx.clearRect(0, 0, w, h);

    for (const b of blobsRef.current) {
      b.x += Math.sin(t * 0.3 + b.phase) * b.vx;
      b.y += Math.cos(t * 0.2 + b.phase) * b.vy;

      if (b.x < -b.r) b.x = w + b.r;
      if (b.x > w + b.r) b.x = -b.r;
      if (b.y < -b.r) b.y = h + b.r;
      if (b.y > h + b.r) b.y = -b.r;

      const gradient = ctx.createRadialGradient(b.x, b.y, 0, b.x, b.y, b.r);
      gradient.addColorStop(0, "rgba(255, 59, 48, 0.04)");
      gradient.addColorStop(1, "rgba(255, 59, 48, 0)");

      ctx.fillStyle = gradient;
      ctx.beginPath();
      ctx.arc(b.x, b.y, b.r, 0, Math.PI * 2);
      ctx.fill();
    }
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const resize = () => {
      const dpr = window.devicePixelRatio || 1;
      const rect = canvas.getBoundingClientRect();
      canvas.width = rect.width * dpr;
      canvas.height = rect.height * dpr;
      ctx.scale(dpr, dpr);
      init(canvas);
    };

    resize();
    window.addEventListener("resize", resize);

    const loop = () => {
      if (visibleRef.current) {
        draw(canvas, ctx);
      }
      rafRef.current = requestAnimationFrame(loop);
    };
    rafRef.current = requestAnimationFrame(loop);

    const observer = new IntersectionObserver(([entry]) => {
      if (entry) visibleRef.current = entry.isIntersecting;
    }, { threshold: 0 });

    observer.observe(canvas);

    return () => {
      cancelAnimationFrame(rafRef.current);
      window.removeEventListener("resize", resize);
      observer.disconnect();
    };
  }, [init, draw]);

  return (
    <canvas
      ref={canvasRef}
      className="pointer-events-none absolute inset-0 h-full w-full"
      aria-hidden="true"
    />
  );
}
