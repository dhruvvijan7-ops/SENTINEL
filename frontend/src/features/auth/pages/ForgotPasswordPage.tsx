import { useState } from "react";
import type { FormEvent } from "react";
import { Link } from "react-router-dom";
import { CheckCircle2, Mail } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

import { authService } from "@/services/authService";
import { ROUTES } from "@/routes/paths";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isSent, setIsSent] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setIsLoading(true);

    try {
      await authService.forgotPassword(email);
      setIsSent(true);
    } catch {
      setError("Something went wrong. Please try again.");
    } finally {
      setIsLoading(false);
    }
  }

  if (isSent) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-transparent px-4">
        <Card className="ops-surface w-full max-w-md">
          <CardHeader className="space-y-4">
            <div className="flex justify-center">
              <div className="flex size-12 items-center justify-center rounded-lg bg-success/10 text-success">
                <CheckCircle2 className="size-6" />
              </div>
            </div>
            <div className="text-center">
              <CardTitle className="text-2xl">Check your email</CardTitle>
              <CardDescription className="mt-2">
                If an account exists with <strong>{email}</strong>, a password reset link has been sent.
              </CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            <Link to={ROUTES.login}>
              <Button variant="outline" className="w-full">
                Back to sign in
              </Button>
            </Link>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-transparent px-4">
      <Card className="ops-surface w-full max-w-md">
        <CardHeader className="space-y-4">
          <div className="flex justify-center">
            <div className="flex size-12 items-center justify-center rounded-lg bg-primary text-primary-foreground">
              <Mail className="size-6" />
            </div>
          </div>

          <div className="text-center">
            <CardTitle className="text-2xl">
              Forgot your password?
            </CardTitle>

            <CardDescription className="mt-2">
              Enter your email and we&apos;ll send you a reset link.
            </CardDescription>
          </div>
        </CardHeader>

        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="analyst@sentinelai.local"
                required
              />
            </div>

            {error && (
              <p className="text-sm text-destructive" role="alert">
                {error}
              </p>
            )}

            <Button type="submit" className="w-full" disabled={isLoading}>
              {isLoading ? "Sending..." : "Send reset link"}
            </Button>

            <div className="text-center text-sm">
              <Link
                to={ROUTES.login}
                className="text-muted-foreground underline-offset-4 hover:underline"
              >
                Back to sign in
              </Link>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
