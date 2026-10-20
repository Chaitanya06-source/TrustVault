import React, { useState, useEffect } from 'react';
import { X, UserPlus, Shield, Trash2, Sparkles, AlertCircle, CheckCircle2, Lock, UserCheck } from 'lucide-react';
import { api } from '../api/client';

interface PermissionsModalProps {
  documentId: string;
  documentTitle: string;
  isOpen: boolean;
  onClose: () => void;
}

export const PermissionsModal: React.FC<PermissionsModalProps> = ({
  documentId,
  documentTitle,
  isOpen,
  onClose
}) => {
  const [permissions, setPermissions] = useState<any[]>([]);
  const [availableUsers, setAvailableUsers] = useState<any[]>([]);
  const [selectedUserId, setSelectedUserId] = useState('');
  const [selectedLevel, setSelectedLevel] = useState<'view' | 'edit'>('view');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // AI Access Advisor state
  const [aiLoading, setAiLoading] = useState(false);
  const [aiRecommendation, setAiRecommendation] = useState<any>(null);

  useEffect(() => {
    if (isOpen) {
      loadData();
    }
  }, [isOpen, documentId]);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [permRes, userRes] = await Promise.all([
        api.listPermissions(documentId),
        api.listUsers()
      ]);
      setPermissions(permRes.permissions || []);
      setAvailableUsers(userRes.users || []);
      if (userRes.users && userRes.users.length > 0) {
        setSelectedUserId(userRes.users[0].id);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load permissions');
    } finally {
      setLoading(false);
    }
  };

  const handleGrant = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedUserId) return;

    setError(null);
    setSuccessMsg(null);
    try {
      await api.grantPermission(documentId, selectedUserId, selectedLevel);
      setSuccessMsg(`Permission '${selectedLevel}' granted with immediate effect.`);
      await loadData();
    } catch (err: any) {
      setError(err.message || 'Failed to grant permission');
    }
  };

  const handleRevoke = async (userId: string, userName: string) => {
    setError(null);
    setSuccessMsg(null);
    try {
      await api.revokePermission(documentId, userId);
      setSuccessMsg(`Access for ${userName} REVOKED IMMEDIATELY. Next request will be denied.`);
      await loadData();
    } catch (err: any) {
      setError(err.message || 'Failed to revoke permission');
    }
  };

  const handleAiAdvisory = async () => {
    setAiLoading(true);
    setError(null);
    try {
      const res = await api.getAiRecommendation({
        documentTitle,
        category: 'Legal', // Default or fetch doc
        documentId
      });
      setAiRecommendation(res.recommendation);
    } catch (err: any) {
      setError(err.message || 'AI analysis failed');
    } finally {
      setAiLoading(false);
    }
  };

  const handleApplyAiSuggestion = async () => {
    if (!aiRecommendation) return;
    setError(null);
    setSuccessMsg(null);
    try {
      const confirmedGrants = aiRecommendation.suggestedRecipients
        .filter((r: any) => r.recommendedPermission !== 'none')
        .map((r: any) => ({
          userId: r.userId,
          permissionLevel: r.recommendedPermission
        }));

      await api.confirmAiDecision({
        documentId,
        advisoryId: aiRecommendation.advisoryId,
        decision: 'ACCEPTED',
        confirmedGrants
      });

      setSuccessMsg(`Applied AI least-privilege recommendation. Human confirmation recorded in audit log.`);
      setAiRecommendation(null);
      await loadData();
    } catch (err: any) {
      setError(err.message || 'Failed to apply AI suggestions');
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-xl w-full overflow-hidden shadow-2xl animate-in fade-in zoom-in-95 duration-150 max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/60">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-emerald-400" />
            <div>
              <h2 className="text-sm font-semibold text-white">Document Access & Permissions</h2>
              <p className="text-xs text-slate-400 truncate max-w-sm">{documentTitle}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 transition p-1 rounded-md hover:bg-slate-800"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-5 overflow-y-auto flex-1">
          {error && (
            <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg flex items-start gap-2.5 text-xs text-rose-300">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {successMsg && (
            <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg flex items-start gap-2.5 text-xs text-emerald-300">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <span>{successMsg}</span>
            </div>
          )}

          {/* AI Advisor Button */}
          <div className="bg-emerald-950/20 border border-emerald-500/20 rounded-lg p-3.5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-emerald-400" />
                <span className="text-xs font-semibold text-emerald-300">AI Least-Privilege Access Advisor</span>
              </div>
              <button
                type="button"
                onClick={handleAiAdvisory}
                disabled={aiLoading}
                className="px-2.5 py-1 text-xs bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/30 rounded font-medium transition flex items-center gap-1"
              >
                {aiLoading ? 'Analyzing...' : 'Generate Recommendations'}
              </button>
            </div>

            {aiRecommendation && (
              <div className="mt-3 pt-3 border-t border-emerald-500/20 text-xs space-y-2">
                <p className="text-slate-300 text-[11px] leading-relaxed">
                  {aiRecommendation.securityRationale}
                </p>
                <div className="space-y-1">
                  <span className="text-[11px] font-semibold text-slate-400">Proposed Grants:</span>
                  {aiRecommendation.suggestedRecipients.map((r: any) => (
                    <div key={r.userId} className="flex items-center justify-between bg-slate-950/60 p-1.5 rounded text-[11px]">
                      <span className="text-slate-300 font-medium">{r.userName} ({r.userEmail})</span>
                      <span className={`px-1.5 py-0.5 rounded font-mono text-[10px] uppercase font-bold ${
                        r.recommendedPermission === 'none' ? 'bg-rose-500/20 text-rose-300' : 'bg-emerald-500/20 text-emerald-300'
                      }`}>
                        {r.recommendedPermission}
                      </span>
                    </div>
                  ))}
                </div>
                <div className="flex items-center justify-between pt-2">
                  <span className="text-[10px] text-slate-400 italic">Confirmation recorded into immutable audit chain</span>
                  <button
                    type="button"
                    onClick={handleApplyAiSuggestion}
                    className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-semibold transition"
                  >
                    Confirm & Apply Grants
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Current Grants Table */}
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-emerald-400" />
              Active Grants ({permissions.length})
            </h3>

            {permissions.length === 0 ? (
              <div className="p-4 rounded-lg bg-slate-950/40 border border-slate-800 text-center text-xs text-slate-500">
                No external users currently have permission to access this document.
              </div>
            ) : (
              <div className="border border-slate-800 rounded-lg overflow-hidden divide-y divide-slate-800">
                {permissions.map(p => (
                  <div key={p.id} className="p-3 bg-slate-950/40 flex items-center justify-between">
                    <div>
                      <div className="text-xs font-medium text-slate-200">{p.user_name}</div>
                      <div className="text-[11px] text-slate-400 font-mono">{p.user_email}</div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-semibold border ${
                        p.permission_level === 'edit'
                          ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                          : 'bg-blue-500/20 text-blue-300 border-blue-500/30'
                      }`}>
                        {p.permission_level}
                      </span>
                      <button
                        onClick={() => handleRevoke(p.user_id, p.user_name)}
                        className="p-1 text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 rounded transition"
                        title="Revoke Immediately"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Grant New Permission Form */}
          <form onSubmit={handleGrant} className="pt-3 border-t border-slate-800 space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <UserPlus className="w-3.5 h-3.5 text-emerald-400" />
              Grant New Access
            </h3>

            <div className="grid grid-cols-3 gap-2">
              <div className="col-span-2">
                <select
                  value={selectedUserId}
                  onChange={e => setSelectedUserId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
                >
                  <option value="">Select Named Recipient...</option>
                  {availableUsers.map(u => (
                    <option key={u.id} value={u.id}>
                      {u.name} ({u.email}) - {u.role}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <select
                  value={selectedLevel}
                  onChange={e => setSelectedLevel(e.target.value as any)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
                >
                  <option value="view">Read / Download (View)</option>
                  <option value="edit">Edit / Update Version</option>
                </select>
              </div>
            </div>

            <button
              type="submit"
              disabled={!selectedUserId}
              className="w-full py-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg text-xs font-medium transition shadow-sm"
            >
              Grant Access Immediately
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
