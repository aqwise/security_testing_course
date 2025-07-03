const isProd = process.env.NODE_ENV === 'production';
const basePath = isProd ? '/security_testing_course' : '';

export function getImagePath(imagePath: string): string {
  // Remove leading slash if present
  const cleanPath = imagePath.startsWith('/') ? imagePath.slice(1) : imagePath;
  return `${basePath}/${cleanPath}`;
}

export function getAssetPath(assetPath: string): string {
  // Remove leading slash if present
  const cleanPath = assetPath.startsWith('/') ? assetPath.slice(1) : assetPath;
  return `${basePath}/${cleanPath}`;
} 