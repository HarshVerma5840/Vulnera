import ParticleBackground from '@/components/ui/particle-background';

export function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="relative min-h-screen w-full flex items-center justify-center bg-background overflow-hidden">
      <ParticleBackground density={14000} interactive={true} />
      <div className="relative z-10 w-full max-w-md px-4">
        {children}
      </div>
    </div>
  );
}
