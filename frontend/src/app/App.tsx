import AppProviders from "@/app/providers/AppProviders";
import AppRouter from "@/app/router/AppRouter";
import AuthInitializer from "@/components/AuthInitializer";

export default function App() {
  return (
    <AppProviders>
      <AuthInitializer>
        <AppRouter />
      </AuthInitializer>
    </AppProviders>
  );
}