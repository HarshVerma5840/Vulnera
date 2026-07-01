import { useState } from 'react';
import { Link, Navigate } from 'react-router-dom';
import { Shield, Loader2, ChevronLeft, Github } from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import ParticleBackground from '@/components/ui/particle-background';

export default function LoginPage() {
  const { login, register, isLoggedIn } = useAuth();
  const [step, setStep] = useState(1);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  if (isLoggedIn) return <Navigate to="/scan" replace />;

  const handleEmailSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (email.trim()) setStep(2);
  };

  const handleAuth = async (action: 'login' | 'register') => {
    if (!password) {
      setError('Please enter a password');
      return;
    }
    setError('');
    setLoading(true);
    try {
      if (action === 'login') {
        await login(email.trim(), password);
      } else {
        await register(email.trim(), password);
      }
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail || `${action === 'login' ? 'Login' : 'Registration'} failed`;
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen w-full bg-background">
      
      {/* Left Column - Branding & Particles */}
      <div className="hidden lg:flex flex-col justify-between w-1/2 p-12 relative overflow-hidden bg-[#0A0A0A]">
        <ParticleBackground density={9000} interactive={true} />
        
        {/* Logo */}
        <div className="relative z-10 flex items-center gap-2">
          <Shield className="h-6 w-6 text-foreground" />
          <span className="text-xl font-bold tracking-tight text-foreground">Vulnera</span>
        </div>

        {/* Quote */}
        <div className="relative z-10 max-w-lg">
          <p className="text-2xl font-medium text-muted-foreground leading-relaxed">
            "This Platform has helped me to save time and serve my clients faster than ever before."
          </p>
          <p className="mt-6 font-bold text-foreground">~ Security Team</p>
        </div>
      </div>

      {/* Right Column - Form */}
      <div className="w-full lg:w-1/2 flex flex-col p-8 sm:p-12 md:p-16">
        
        {/* Back Link */}
        <div className="mb-12">
          <Link to="/" className="inline-flex items-center text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">
            <ChevronLeft className="h-4 w-4 mr-1" /> Home
          </Link>
        </div>

        <div className="w-full max-w-md mx-auto flex-1 flex flex-col justify-center">
          
          <div className="text-center mb-8">
            <h1 className="text-2xl font-bold text-foreground mb-2">Sign In or Join Now!</h1>
            <p className="text-sm text-muted-foreground">login or create your vulnera account.</p>
          </div>

          <div className="space-y-3 mb-8">
            <Button variant="secondary" className="w-full bg-foreground text-background hover:bg-foreground/90 h-11" onClick={() => {}}>
              <svg className="w-5 h-5 mr-2" viewBox="0 0 24 24" fill="currentColor">
                <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
                <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
              </svg>
              Continue with Google
            </Button>
            
            <Button variant="secondary" className="w-full bg-foreground text-background hover:bg-foreground/90 h-11" onClick={() => {}}>
              <Github className="w-5 h-5 mr-2" />
              Continue with GitHub
            </Button>
          </div>

          <div className="relative mb-8">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-border"></div>
            </div>
            <div className="relative flex justify-center text-xs uppercase">
              <span className="bg-background px-2 text-muted-foreground">OR</span>
            </div>
          </div>

          {error && (
            <div className="mb-4 p-3 rounded-md bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
              {error}
            </div>
          )}

          {step === 1 ? (
            <form onSubmit={handleEmailSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="email" className="sr-only">Email</Label>
                <p className="text-sm text-muted-foreground mb-1">Enter your email address to sign in or create an account</p>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none text-muted-foreground">
                    @
                  </div>
                  <Input
                    id="email"
                    type="email"
                    placeholder="your.email@example.com"
                    className="pl-9 h-11 bg-transparent border-input focus-visible:ring-1 focus-visible:ring-foreground"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                  />
                </div>
              </div>

              <Button type="submit" className="w-full h-11 text-base bg-foreground text-background hover:bg-foreground/90">
                Continue With Email
              </Button>
            </form>
          ) : (
            <div className="space-y-4">
              <div className="space-y-2">
                <p className="text-sm text-muted-foreground mb-1">Enter a password for <strong>{email}</strong></p>
                <Input
                  id="password"
                  type="password"
                  placeholder="••••••••"
                  className="h-11 bg-transparent border-input focus-visible:ring-1 focus-visible:ring-foreground"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>

              <div className="flex gap-3">
                <Button 
                  type="button" 
                  variant="outline" 
                  className="flex-1 h-11 text-base" 
                  onClick={() => handleAuth('login')} 
                  disabled={loading}
                >
                  {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                  Sign In
                </Button>
                <Button 
                  type="button" 
                  className="flex-1 h-11 text-base bg-foreground text-background hover:bg-foreground/90" 
                  onClick={() => handleAuth('register')} 
                  disabled={loading}
                >
                  {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                  Create Account
                </Button>
              </div>
              <button 
                type="button" 
                onClick={() => {setStep(1); setError('');}} 
                className="text-xs text-muted-foreground hover:text-foreground text-center w-full mt-2"
              >
                Change email address
              </button>
            </div>
          )}

          <p className="text-xs text-muted-foreground mt-8">
            By clicking continue, you agree to our <a href="#" className="underline hover:text-foreground">Terms of Service</a> and <a href="#" className="underline hover:text-foreground">Privacy Policy</a>.
          </p>

        </div>
      </div>
    </div>
  );
}
