/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "export",
  // Assets must load with RELATIVE paths — the packaged app opens the export
  // over file://, where Next's default absolute "/_next/..." URLs resolve to
  // the filesystem root and 404 (so no CSS/JS → the "broken, unstyled" GUI).
  // "." makes them relative to index.html instead.
  assetPrefix: ".",
  images: { unoptimized: true },
  // distDir intentionally left at the default (.next). Pointing it at "out"
  // collided with the static-export output dir (also "out"), so the export's
  // index.html never got written and the packaged window loaded a broken page.
};

export default nextConfig;
