import React, { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Navbar } from './components/Navbar';
import { DocumentsPage } from './pages/DocumentsPage';
import { AuditPage } from './pages/AuditPage';
import { AdminPage } from './pages/AdminPage';
import { ThreatModelPage } from './pages/ThreatModelPage';

const AppContent: React.FC = () => {
  const { user, loading } = useAuth();
  const [activeTab, setActiveTab] = useState<'documents' | 'audit' | 'admin' | 'threats'>('documents');

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center text-slate-400 text-sm">
        Initializing TrustVault Zero-Trust Security Core...
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col">
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} />
      <main className="flex-1">
        {activeTab === 'documents' && <DocumentsPage />}
        {activeTab === 'audit' && <AuditPage />}
        {activeTab === 'admin' && <AdminPage />}
        {activeTab === 'threats' && <ThreatModelPage />}
      </main>
      <footer className="border-t border-slate-800/80 py-4 text-center text-xs text-slate-500">
        TrustVault Platform • Zero-Trust Access Gateway & Cryptographic Audit Ledger • Seven-Day Sprint
      </footer>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
};

export default App;
