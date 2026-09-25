import { useState } from "react";
import type { FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { CheckCircle2, KeyRound } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

import { authService } from "@/services/authService";
import { ApiError } from "@/services/apiClient";
import { ROUTES } from "@/routes/paths";

export default function ResetPasswordPage() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token") ?? "";

  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isDone, setIsDone] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");

    if (password.length < 8) {
      setError("Password must contain at least 8 characters.");
      return;
    }

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setIsLoading(true);

    try {
      await authService.resetPassword({ token, new_password: password });
      setIsDone(true);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("Unable to reach the server. Please try again.");
      }
    } finally {
      setIsLoading(false);
    }
  }

  if (isDone) {
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
              <CardTitle className="text-2xl">Password reset</CardTitle>
              <CardDescription className="mt-2">
                Your password has been updated. You can now sign in with your new password.
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

  if (!token) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-transparent px-4">
        <Card className="ops-surface w-full max-w-md">
          <CardHeader className="space-y-4">
            <div className="flex justify-center">
              <div className="flex size-12 items-center justify-center rounded-lg bg-destructive/10 text-destructive">
                <KeyRound className="size-6" />
              </div>
            </div>
            <div className="text-center">
              <CardTitle className="text-2xl">Invalid reset link</CardTitle>
              <CardDescription className="mt-2">
                This reset link is missing its token. Please request a new one.
              </CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            <Link to={ROUTES.forgotPassword}>
              <Button className="w-full">Request a new link</Button>
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
              <KeyRound className="size-6" />
            </div>
          </div>

          <div className="text-center">
            <CardTitle className="text-2xl">
              Choose a new password
            </CardTitle>

            <CardDescription className="mt-2">
              Enter a new password for your account.
            </CardDescription>
          </div>
        </CardHeader>

        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="space-y-2">
              <Label htmlFor="password">New password</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="At least 8 characters"
                required
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="confirmPassword">Confirm password</Label>
              <Input
                id="confirmPassword"
                type="password"
                value={confirmPassword}
                onChange={(event) => setConfirmPassword(event.target.value)}
                placeholder="Re-enter your password"
                required
              />
            </div>

            {error && (
              <p className="text-sm text-destructive" role="alert">
                {error}
              </p>
            )}

            <Button type="submit" className="w-full" disabled={isLoading}>
              {isLoading ? "Resetting..." : "Reset password"}
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