/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Standalone output keeps the Docker image small (only the server bundle + node_modules it actually needs).
  output: "standalone",
};
export default nextConfig;
