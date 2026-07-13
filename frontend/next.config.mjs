/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Собираемся в standalone для лёгкого Docker-образа.
  output: "standalone",
};

export default nextConfig;
