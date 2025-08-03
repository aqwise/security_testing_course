
'use client';

interface YouTubePlayerProps {
  videoId: string;
  className?: string;
}

export function YouTubePlayer({ videoId, className }: YouTubePlayerProps) {
  const src = `https://www.youtube.com/embed/${videoId}`;
  return (
    <div className={`relative overflow-hidden w-full pt-[56.25%] rounded-lg shadow-lg ${className}`}>
      <iframe
        className="absolute top-0 left-0 bottom-0 right-0 w-full h-full"
        src={src}
        title="YouTube video player"
        frameBorder="0"
        allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
        allowFullScreen
      ></iframe>
    </div>
  );
}
