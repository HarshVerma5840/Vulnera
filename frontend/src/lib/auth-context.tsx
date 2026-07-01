import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { authApi, type AuthResponse } from './api';

interface AuthState {
  token: string | null;
  email: string | null;
  userId: number | null;
  isLoading: boolean;
  isLoggedIn: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string | null>(localStorage.getItem('vulnera_token'));
  const [email, setEmail] = useState<string | null>(localStorage.getItem('vulnera_email'));
  const [userId, setUserId] = useState<number | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Verify token on mount
  useEffect(() => {
    if (!token) {
      setIsLoading(false);
      return;
    }
    authApi.me()
      .then((res) => {
        setEmail(res.data.email);
        setUserId(res.data.user_id);
      })
      .catch(() => {
        // Token invalid — clear session
        localStorage.removeItem('vulnera_token');
        localStorage.removeItem('vulnera_email');
        setToken(null);
        setEmail(null);
      })
      .finally(() => setIsLoading(false));
  }, [token]);

  const saveSession = useCallback((data: AuthResponse) => {
    localStorage.setItem('vulnera_token', data.token);
    localStorage.setItem('vulnera_email', data.email);
    setToken(data.token);
    setEmail(data.email);
    setUserId(data.user_id);
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const res = await authApi.login(email, password);
    saveSession(res.data);
  }, [saveSession]);

  const register = useCallback(async (email: string, password: string) => {
    const res = await authApi.register(email, password);
    saveSession(res.data);
  }, [saveSession]);

  const logout = useCallback(() => {
    localStorage.removeItem('vulnera_token');
    localStorage.removeItem('vulnera_email');
    setToken(null);
    setEmail(null);
    setUserId(null);
  }, []);

  return (
    <AuthContext.Provider
      value={{
        token,
        email,
        userId,
        isLoading,
        isLoggedIn: !!token,
        login,
        register,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
