import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SignalZero | Vulnerability Intelligence",
  description: "Cybersecurity vulnerability prediction and prioritization command center.",
  icons: { icon: "/favicon.svg", shortcut: "/favicon.svg" },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body className="antialiased">{children}</body></html>;
}
