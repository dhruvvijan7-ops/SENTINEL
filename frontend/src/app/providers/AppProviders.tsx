import type { ReactNode } from "react";

import QueryProvider from "./QueryProvider";
import ThemeProvider from "./ThemeProvider";

interface AppProvidersProps {
  children: ReactNode;
}

export default function AppProviders({
  children,
}: AppProvidersProps) {
  return (
    <ThemeProvider>
      <QueryProvider>{children}</QueryProvider>
    </ThemeProvider>
  );
}