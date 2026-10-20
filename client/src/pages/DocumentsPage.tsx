import React, { useState, useEffect } from 'react';
import {
  Search,
  Filter,
  Plus,
  Download,
  Shield,
  Clock,
  User,
  Trash2,
  FileText,
  Lock,
  Edit3,
  AlertCircle,
  Eye,
  FileCheck
} from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { UploadModal } from '../components/UploadModal';
import { PermissionsModal } from '../components/PermissionsModal';

export const DocumentsPage: React.FC = () => {
  const { user } = useAuth();
  const [documents, setDocuments] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('ALL');

  // Modals
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [permDoc, setPermDoc] = useState<{ id: string; title: string } | null>(null);

  const loadDocuments = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.listDocuments({
        q: searchQuery || undefined,
        category: selectedCategory !== 'ALL' ? selectedCategory : undefined
      });
      setDocuments(res.documents || []);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch documents');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDocuments();
  }, [user, selectedCategory]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadDocuments();
  };

  const handleDownload = async (doc: any) => {
    try {
      await api.downloadDocument(doc.id, doc.original_filename);
    } catch (err: any) {
      alert(`Download rejected: ${err.message}`);
      loadDocuments();
    }
  };

  const handleDelete = async (doc: any) => {
    if (!confirm(`Permanently delete '${doc.title}' and remove from vault storage?`)) return;
    try {
      await api.deleteDocument(doc.id);
      loadDocuments();
    } catch (err: any) {
      alert(`Deletion rejected: ${err.message}`);
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Top Banner & Stats */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Zero-Trust Document Vault</h1>
          <p className="text-sm text-slate-400 mt-1">
            Access is validated at the database layer on every single byte transfer. Server decides every time.
          </p>
        </div>

        {user && (user.role === 'owner' || user.role === 'admin') && (
          <button
            onClick={() => setIsUploadOpen(true)}
            className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-semibold transition shadow-md shadow-emerald-600/30 self-start md:self-auto"
          >
            <Plus className="w-4 h-4" />
            <span>Upload Document</span>
          </button>
        )}
      </div>

      {/* Role explanation alert */}
      <div className="p-3.5 bg-slate-900/80 border border-slate-800 rounded-lg flex items-center justify-between text-xs text-slate-300">
        <div className="flex items-center gap-2.5">
          <Shield className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>
            Viewing as <strong className="text-white">{user?.name}</strong> ({user?.role}).
            {user?.email === 'eve@external.org' ? (
              <span className="text-rose-400 font-medium ml-1">
                You have NO grants. All access probes will return HTTP 403 and append a permanent refusal to the audit ledger.
              </span>
            ) : user?.role === 'viewer' ? (
              <span className="text-blue-300 font-medium ml-1">
                Only documents explicitly granted to you are visible. Private executive papers remain hidden.
              </span>
            ) : (
              <span className="text-emerald-300 font-medium ml-1">
                You can manage permissions and revoke access with instant effect.
              </span>
            )}
          </span>
        </div>
      </div>

      {/* Search & Category Filter Toolbar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search documents by title, description, or filename..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-sm font-medium transition"
          >
            Search
          </button>
        </form>

        {/* Category Pills */}
        <div className="flex items-center gap-1.5 overflow-x-auto text-xs pt-1">
          <span className="text-slate-500 font-medium mr-1 flex items-center gap-1">
            <Filter className="w-3 h-3" /> Category:
          </span>
          {['ALL', 'Legal', 'Financial', 'HR', 'Executive', 'Engineering'].map(cat => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-3 py-1 rounded-full font-medium transition ${
                selectedCategory === cat
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                  : 'bg-slate-950 border border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              {cat === 'ALL' ? 'All Categories' : cat}
            </button>
          ))}
        </div>
      </div>

      {/* Document Grid */}
      {error && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/30 rounded-xl text-rose-300 text-sm flex items-center gap-3">
          <AlertCircle className="w-5 h-5 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="p-12 text-center text-slate-500 text-sm">
          Loading encrypted documents from vault...
        </div>
      ) : documents.length === 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center space-y-3">
          <div className="p-3 bg-slate-800/50 rounded-full w-12 h-12 mx-auto flex items-center justify-center text-slate-400">
            <Lock className="w-6 h-6" />
          </div>
          <h3 className="text-base font-semibold text-white">No Accessible Documents</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            {user?.email === 'eve@external.org'
              ? 'Eve holds 0 permissions. Under Zero-Trust principles, unpermitted documents are invisible in listings and rejected on direct requests.'
              : 'No documents match your active permissions or filter criteria.'}
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {documents.map(doc => {
            const isOwner = doc.user_permission === 'owner';
            const isEditor = doc.user_permission === 'editor';
            const isViewer = doc.user_permission === 'viewer';

            return (
              <div
                key={doc.id}
                className="bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-xl p-5 shadow-sm transition flex flex-col justify-between"
              >
                <div>
                  {/* Category & Classification header */}
                  <div className="flex items-center justify-between gap-2 mb-3">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase bg-slate-800 text-slate-300 border border-slate-700">
                      {doc.category}
                    </span>

                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                        doc.classification === 'Confidential'
                          ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                          : doc.classification === 'Restricted'
                          ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                          : 'bg-blue-500/20 text-blue-300 border-blue-500/30'
                      }`}
                    >
                      {doc.classification}
                    </span>
                  </div>

                  {/* Title & Description */}
                  <h3 className="text-sm font-semibold text-white leading-snug line-clamp-2">
                    {doc.title}
                  </h3>
                  {doc.description && (
                    <p className="text-xs text-slate-400 mt-1 line-clamp-2 leading-relaxed">
                      {doc.description}
                    </p>
                  )}

                  {/* Metadata pills */}
                  <div className="mt-3.5 pt-3 border-t border-slate-800/80 space-y-1.5 text-[11px] text-slate-400">
                    <div className="flex items-center justify-between">
                      <span className="flex items-center gap-1.5">
                        <FileText className="w-3.5 h-3.5 text-slate-500" />
                        <span className="truncate max-w-[140px] font-mono">{doc.original_filename}</span>
                      </span>
                      <span className="font-mono">{(doc.file_size_bytes / 1024).toFixed(1)} KB (v{doc.version})</span>
                    </div>

                    <div className="flex items-center justify-between">
                      <span className="flex items-center gap-1.5">
                        <User className="w-3.5 h-3.5 text-slate-500" />
                        <span>Owner: {doc.owner_name?.split(' ')[0] || 'Internal'}</span>
                      </span>
                      <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono uppercase font-semibold ${
                        isOwner ? 'text-emerald-400' : isEditor ? 'text-amber-400' : 'text-blue-400'
                      }`}>
                        Your access: {doc.user_permission}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Card Actions */}
                <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between gap-2">
                  <button
                    onClick={() => handleDownload(doc)}
                    className="flex-1 flex items-center justify-center gap-1.5 py-1.5 px-3 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 rounded-lg text-xs font-semibold transition"
                    title="Download securely (Server evaluates permission on byte stream)"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download</span>
                  </button>

                  {isOwner && (
                    <button
                      onClick={() => setPermDoc({ id: doc.id, title: doc.title })}
                      className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded-lg text-xs font-medium transition"
                      title="Manage permissions & instant revocation"
                    >
                      <Lock className="w-3.5 h-3.5" />
                    </button>
                  )}

                  {isOwner && (
                    <button
                      onClick={() => handleDelete(doc)}
                      className="p-1.5 text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 rounded-lg transition"
                      title="Delete document"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Upload Modal */}
      <UploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onSuccess={loadDocuments}
      />

      {/* Permissions & Revocation Modal */}
      {permDoc && (
        <PermissionsModal
          documentId={permDoc.id}
          documentTitle={permDoc.title}
          isOpen={true}
          onClose={() => setPermDoc(null)}
        />
      )}
    </div>
  );
};
