import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  devIndicators: false,
  serverExternalPackages: ["@prisma/client", "@prisma/adapter-libsql"],
  experimental: {
    proxyClientMaxBodySize: "100mb",
  },
};

export default nextConfig;
