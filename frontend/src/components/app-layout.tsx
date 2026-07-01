import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '@/lib/auth-context';
import { Shield, Search, Clock, LogOut } from 'lucide-react';
import { Button } from '@/components/ui/button';
import ParticleBackground from '@/components/ui/particle-background';

const navLinks = [
  { to: '/scan', label: 'Scan', icon: Search },
  { to: '/history', label: 'History', icon: Clock },
];

export function AppLayout({ children }: { children: React.ReactNode }) {
  const { email, logout } = useAuth();
  const location = useLocation();

  return (
    <div className="relative min-h-screen w-full bg-background">
      {/* Subtle particle background */}
      <ParticleBackground density={25000} interactive={false} particleColor="rgba(139, 92, 246, 0.3)" />

      {/* Navigation */}
      <nav className="relative z-20 border-b border-border/50 backdrop-blur-md bg-background/80">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-14">
            {/* Logo */}
            <Link to="/scan" className="flex items-center gap-2.5 group">
              <div className="w-8 h-8 rounded-lg bg-primary/20 border border-primary/30 flex items-center justify-center group-hover:bg-primary/30 transition-colors">
                <Shield className="h-4 w-4 text-primary" />
              </div>
              <span className="text-lg font-bold text-foreground tracking-tight">
                Vulnera<span className="text-primary">.</span>
              </span>
            </Link>

            {/* Center nav links */}
            <div className="flex items-center gap-1">
              {navLinks.map((link) => {
                const isActive = location.pathname === link.to;
                return (
                  <Link
                    key={link.to}
                    to={link.to}
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                      isActive
                        ? 'bg-primary/15 text-primary'
                        : 'text-muted-foreground hover:text-foreground hover:bg-accent'
                    }`}
                  >
                    <link.icon className="h-4 w-4" />
                    {link.label}
                  </Link>
                );
              })}
            </div>

            {/* User info */}
            <div className="flex items-center gap-3">
              <span className="text-sm text-muted-foreground hidden sm:block">
                {email}
              </span>
              <Button variant="ghost" size="sm" onClick={logout} className="text-muted-foreground hover:text-foreground">
                <LogOut className="h-4 w-4" />
                <span className="hidden sm:inline">Logout</span>
              </Button>
            </div>
          </div>
        </div>
      </nav>

      {/* Main content */}
      <main className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {children}
      </main>
    </div>
  );
}
