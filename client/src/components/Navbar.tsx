import React from 'react';
import { ShieldCheck, ShieldAlert, FileText, Activity, Key, LogOut, Lock, UserCheck } from 'lucide-react';
import { useAuth, PRESET_PERSONAS } from '../context/AuthContext';

interface NavbarProps {
  activeTab: 'documents' | 'audit' | 'admin' | 'threats';
  setActiveTab: (tab: 'documents' | 'audit' | 'admin' | 'threats') => void;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, setActiveTab }) => {
  const { user, switchPersona, logout } = useAuth();

  return (
    <header className="sticky top-0 z-40 bg-slate-900/90 backdrop-blur border-b border-slate-800">
      {/* Persona quick switch banner for judges */}
      <div className="bg-slate-950 border-b border-slate-800/80 px-4 py-1.5 flex flex-wrap items-center justify-between text-xs gap-2">
        <div className="flex items-center gap-2 text-slate-400">
          <Key className="w-3.5 h-3.5 text-emerald-400" />
          <span className="font-semibold text-slate-300">Fast Persona Switcher:</span>
          <span className="hidden sm:inline text-slate-500">(Instantly test permissions as any role)</span>
        </div>

        <div className="flex items-center gap-1.5 overflow-x-auto py-0.5">
          {PRESET_PERSONAS.map(p => {
            const isActive = user?.email === p.email;
            return (
              <button
                key={p.email}
                onClick={() => switchPersona(p.email)}
                className={`px-2.5 py-1 rounded text-xs font-medium border transition-all flex items-center gap-1.5 ${
                  isActive
                    ? `${p.badgeColor} ring-1 ring-emerald-400 shadow-sm shadow-emerald-500/20`
                    : 'bg-slate-900 border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-600'
                }`}
                title={p.description}
              >
                {p.role === 'admin' && <ShieldAlert className="w-3 h-3 text-purple-400" />}
                {p.role === 'owner' && <UserCheck className="w-3 h-3 text-emerald-400" />}
                {p.role === 'viewer' && p.email.includes('eve') ? (
                  <Lock className="w-3 h-3 text-rose-400" />
                ) : p.role === 'viewer' ? (
                  <FileText className="w-3 h-3 text-blue-400" />
                ) : null}
                <span>{p.name.split(' ')[0]}</span>
                <span className="text-[10px] opacity-75 uppercase">({p.role})</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Main navigation */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <div className="flex items-center gap-3">
            <div className="p-2 bg-emerald-500/10 border border-emerald-500/30 rounded-lg">
              <ShieldCheck className="w-6 h-6 text-emerald-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-lg font-bold text-white tracking-tight">TrustVault</span>
                <span className="px-1.5 py-0.5 text-[10px] uppercase font-mono font-semibold bg-emerald-500/20 text-emerald-300 rounded border border-emerald-500/30">
                  Zero-Trust
                </span>
              </div>
              <p className="text-[11px] text-slate-400">Cryptographic Document Sharing & Tamper-Evident Audit</p>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="flex items-center gap-1 sm:gap-2">
            <button
              onClick={() => setActiveTab('documents')}
              className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition ${
                activeTab === 'documents'
                  ? 'bg-slate-800 text-emerald-400 shadow-sm border border-slate-700'
                  : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
              }`}
            >
              <FileText className="w-4 h-4" />
              <span>Documents</span>
            </button>

            <button
              onClick={() => setActiveTab('audit')}
              className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition ${
                activeTab === 'audit'
                  ? 'bg-slate-800 text-emerald-400 shadow-sm border border-slate-700'
                  : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
              }`}
            >
              <Activity className="w-4 h-4" />
              <span>Audit Ledger</span>
            </button>

            {user?.role === 'admin' && (
              <button
                onClick={() => setActiveTab('admin')}
                className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition ${
                  activeTab === 'admin'
                    ? 'bg-purple-900/40 text-purple-300 shadow-sm border border-purple-700/50'
                    : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
                }`}
              >
                <ShieldAlert className="w-4 h-4 text-purple-400" />
                <span>Admin Alerts</span>
              </button>
            )}

            <button
              onClick={() => setActiveTab('threats')}
              className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition ${
                activeTab === 'threats'
                  ? 'bg-slate-800 text-emerald-400 shadow-sm border border-slate-700'
                  : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
              }`}
            >
              <Lock className="w-4 h-4" />
              <span>Threat Model</span>
            </button>
          </nav>

          {/* Current User Badge */}
          <div className="flex items-center gap-3">
            {user ? (
              <div className="flex items-center gap-3 pl-3 border-l border-slate-800">
                <div className="text-right hidden md:block">
                  <div className="text-xs font-semibold text-white leading-tight">{user.name}</div>
                  <div className="text-[11px] text-slate-400 font-mono">{user.email}</div>
                </div>
                <button
                  onClick={logout}
                  className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded transition"
                  title="Log out"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            ) : null}
          </div>
        </div>
      </div>
    </header>
  );
};
