import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, ArrowRight } from 'lucide-react';
import { Button } from '@/components/ui/button';
import ParticleBackground from '@/components/ui/particle-background';

export default function LandingPage() {
  return (
    <div className="relative min-h-screen w-full bg-background flex flex-col overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 z-0">
        <ParticleBackground density={12000} interactive={true} />
      </div>

      {/* Navigation */}
      <nav className="relative z-10 flex items-center justify-between p-6 lg:px-12">
        <div className="flex items-center gap-2">
          <Shield className="h-6 w-6 text-foreground" />
          <span className="text-xl font-bold tracking-tight text-foreground">Vulnera</span>
        </div>
        <div className="flex gap-4">
          <Button asChild variant="ghost" className="text-muted-foreground hover:text-foreground">
            <Link to="/login">Sign In</Link>
          </Button>
          <Button asChild className="bg-foreground text-background hover:bg-foreground/90">
            <Link to="/login">Get Started</Link>
          </Button>
        </div>
      </nav>

      {/* Hero Content */}
      <main className="relative z-10 flex-1 flex flex-col items-center justify-center px-4 text-center">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="max-w-3xl"
        >
          <div className="inline-flex items-center rounded-full border border-border bg-background/50 px-3 py-1 text-sm font-medium text-muted-foreground mb-8 backdrop-blur-sm">
            <span className="flex h-2 w-2 rounded-full bg-primary mr-2"></span>
            Vulnera 1.0 is now live
          </div>
          
          <h1 className="text-5xl md:text-7xl font-extrabold tracking-tight text-foreground mb-6">
            Intelligent Web <br className="hidden sm:block" />
            <span className="text-muted-foreground">Vulnerability Scanner</span>
          </h1>
          
          <p className="text-lg md:text-xl text-muted-foreground mb-10 max-w-2xl mx-auto leading-relaxed">
            Protect your applications with an advanced, automated security scanner powered by AI. 
            Identify vulnerabilities, analyze risks, and secure your infrastructure instantly.
          </p>
          
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <Button asChild size="lg" className="bg-foreground text-background hover:bg-foreground/90 w-full sm:w-auto h-12 px-8 text-base">
              <Link to="/login">
                Start Scanning <ArrowRight className="ml-2 h-4 w-4" />
              </Link>
            </Button>
            <Button asChild size="lg" variant="outline" className="w-full sm:w-auto h-12 px-8 text-base border-border bg-background/50 backdrop-blur-sm hover:bg-muted">
              <a href="#" target="_blank" rel="noreferrer">
                View Documentation
              </a>
            </Button>
          </div>
        </motion.div>
      </main>

      {/* Footer */}
      <footer className="relative z-10 py-6 text-center text-sm text-muted-foreground">
        <p>&copy; {new Date().getFullYear()} Vulnera Security. All rights reserved.</p>
      </footer>
    </div>
  );
}
