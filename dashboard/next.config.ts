import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  distDir: process.env.NODE_ENV === "development" ? "/tmp/wpc-next" : ".next",
};

export default nextConfig;
