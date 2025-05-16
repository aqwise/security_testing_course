import type {NextConfig} from 'next';

const isProd = process.env.NODE_ENV === 'production';
const repoName = 'security_testing_course'; // Название вашего репозитория
const githubUserName = 'aqwise'; // Ваш никнейм GitHub

const nextConfig: NextConfig = {
  typescript: {
    ignoreBuildErrors: true,
  },
  eslint: {
    ignoreDuringBuilds: true,
  },
  images: {
    unoptimized: true, 
  },
  output: 'export',
  
  basePath: isProd ? `/${repoName}` : undefined,
  assetPrefix: isProd ? `https://${githubUserName}.github.io/${repoName}/` : undefined,
};

export default nextConfig;
