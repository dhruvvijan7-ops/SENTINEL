import { Link } from "react-router-dom";

export default function NotFoundPage() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-background text-foreground">
      <h1 className="text-6xl font-bold">404</h1>

      <p className="text-muted-foreground">Page Not Found</p>

      <Link to="/dashboard" className="text-primary hover:underline">
        Dashboard
      </Link>
    </div>
  );
}
