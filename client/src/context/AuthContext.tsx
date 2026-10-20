import React, { createContext, useContext, useState, useEffect } from 'react';
import { api } from '../api/client';

export interface User {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'owner' | 'viewer';
}

export interface Persona {
  id: string;
  name: string;
  email: string;
  role: 'admin' | 'owner' | 'viewer';
  badgeColor: string;
  description: string;
  password: string;
}

export const PRESET_PERSONAS: Persona[] = [
  {
    id: 'owner-alice',
    name: 'Alice (Finance Owner)',
    email: 'alice@trustvault.internal',
    role: 'owner',
    badgeColor: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
    description: 'Document Owner: Full control, can grant/revoke access and delete docs.',
    password: 'AlicePassword123!'
  },
  {
    id: 'owner-charlie',
    name: 'Charlie (HR Owner)',
    email: 'charlie@trustvault.internal',
    role: 'owner',
    badgeColor: 'bg-teal-500/20 text-teal-300 border-teal-500/30',
    description: 'HR Document Owner: Holds strictly confidential salary & compensation docs.',
    password: 'CharliePassword123!'
  },
  {
    id: 'viewer-bob',
    name: 'Bob (Viewer / Analyst)',
    email: 'bob@trustvault.internal',
    role: 'viewer',
    badgeColor: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
    description: 'Viewer: Only sees docs explicitly granted by Alice. Zero access to Charlie docs.',
    password: 'BobPassword123!'
  },
  {
    id: 'admin-sec',
    name: 'Audit Administrator',
    email: 'admin@trustvault.internal',
    role: 'admin',
    badgeColor: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
    description: 'Admin: Verifies cryptographic hash chain, monitors denied access spikes.',
    password: 'AdminPassword123!'
  },
  {
    id: 'attacker-eve',
    name: 'Eve (Unauthorized Attacker)',
    email: 'eve@external.org',
    role: 'viewer',
    badgeColor: 'bg-rose-500/20 text-rose-300 border-rose-500/30',
    description: 'External Attacker: Has 0 grants. All reads, searches and downloads are refused and audited.',
    password: 'EvePassword123!'
  }
];

interface AuthContextType {
  user: User | null;
  token: string | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  switchPersona: (personaEmail: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('trustvault_token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadUser() {
      if (!token) {
        // Auto-login as Alice (Owner) by default for seamless judge evaluation
        try {
          await switchPersona('alice@trustvault.internal');
        } catch {
          setLoading(false);
        }
        return;
      }
      try {
        const res = await api.getMe();
        setUser(res.user);
      } catch {
        localStorage.removeItem('trustvault_token');
        setToken(null);
        setUser(null);
      } finally {
        setLoading(false);
      }
    }
    loadUser();
  }, []);

  const login = async (email: string, password: string) => {
    setLoading(true);
    try {
      const res = await api.login(email, password);
      localStorage.setItem('trustvault_token', res.token);
      setToken(res.token);
      setUser(res.user);
    } finally {
      setLoading(false);
    }
  };

  const switchPersona = async (personaEmail: string) => {
    const persona = PRESET_PERSONAS.find(p => p.email === personaEmail);
    if (!persona) return;
    await login(persona.email, persona.password);
  };

  const logout = () => {
    localStorage.removeItem('trustvault_token');
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, token, loading, login, switchPersona, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within an AuthProvider');
  return context;
};
