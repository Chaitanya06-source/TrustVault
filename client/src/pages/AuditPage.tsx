import React, { useState, useEffect } from 'react';
import { Activity, ShieldAlert, ShieldCheck, Filter, Key, Lock, Eye, AlertOctagon } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { AuditChainVerifier } from '../components/AuditChainVerifier';

export const AuditPage: React.FC = () => {
  const { user } = useAuth();
  const [logs, setLogs] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [error, setError] = useState<string | null>(null);

  const loadLogs = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getAuditLogs({
        status: statusFilter !== 'ALL' ? statusFilter : undefined,
        action: actionFilter !== 'ALL' ? actionFilter : undefined
      });
      setLogs(res.logs || []);
      setTotal(res.total || 0);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch audit logs');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadLogs();
  }, [user, statusFilter, actionFilter]);

  if (user?.role === 'viewer') {
    return (
      <div className="max-w-4xl mx-auto px-4 py-16 text-center space-y-4">
        <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-full w-12 h-12 mx-auto flex items-center justify-center text-rose-400">
          <Lock className="w-6 h-6" />
        </div>
        <h2 className="text-lg font-bold text-white">Access Denied: Restricted to Auditors & Owners</h2>
        <p className="text-xs text-slate-400 max-w-md mx-auto">
          Under strict compliance policies, the raw audit ledger is only accessible to Security Administrators and Document Owners. Viewers cannot inspect tenant-wide audit streams.
        </p>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Tamper-Evident Audit Ledger</h1>
        <p className="text-sm text-slate-400 mt-1">
          Cryptographically chained records proving who accessed documents, when, and every refused attempt.
        </p>
      </div>

      {/* Cryptographic Chain Integrity Verifier Card */}
      <AuditChainVerifier />

      {/* Filters Toolbar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400 font-medium">Status:</span>
            {['ALL', 'DENIED', 'SUCCESS'].map(st => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-2.5 py-1 rounded font-medium transition ${
                  statusFilter === st
                    ? st === 'DENIED'
                      ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30 font-bold'
                      : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-bold'
                    : 'bg-slate-950 border border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {st === 'DENIED' ? 'Refused / Denied Probes' : st === 'ALL' ? 'All Records' : 'Success'}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-slate-400 font-medium">Action:</span>
            <select
              value={actionFilter}
              onChange={e => setActionFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-200 focus:outline-none focus:border-emerald-500"
            >
              <option value="ALL">All Actions</option>
              <option value="DOCUMENT_DOWNLOAD">Downloads</option>
              <option value="DOCUMENT_UPLOAD">Uploads</option>
              <option value="PERMISSION_GRANTED">Permissions Granted</option>
              <option value="PERMISSION_REVOKED">Permissions Revoked</option>
              <option value="ACCESS_DENIED_DOWNLOAD">Refused Downloads</option>
              <option value="ACCESS_DENIED_VIEW">Refused Views</option>
              <option value="AUTH_LOGIN_SUCCESS">Logins</option>
            </select>
          </div>
        </div>

        <div className="text-slate-400">
          Showing <span className="font-semibold text-white">{logs.length}</span> of {total} records
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/70 text-slate-400 uppercase tracking-wider font-semibold">
                <th className="py-3 px-4"># Seq</th>
                <th className="py-3 px-4">Timestamp (UTC)</th>
                <th className="py-3 px-4">Actor</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Target Document / Subject</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Cryptographic Hash</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 font-mono">
              {loading ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-sans">
                    Loading cryptographic ledger records...
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-sans">
                    No audit records match the selected filter.
                  </td>
                </tr>
              ) : (
                logs.map(log => {
                  const isDenied = log.status === 'DENIED';
                  return (
                    <tr
                      key={log.id}
                      className={`hover:bg-slate-800/40 transition ${
                        isDenied ? 'bg-rose-950/20' : ''
                      }`}
                    >
                      <td className="py-2.5 px-4 font-bold text-slate-300">
                        {log.sequence_number}
                      </td>
                      <td className="py-2.5 px-4 text-slate-400 text-[11px]">
                        {new Date(log.timestamp).toISOString().replace('T', ' ').substring(0, 19)}
                      </td>
                      <td className="py-2.5 px-4 font-sans">
                        <div className="font-semibold text-slate-200">{log.actor_email}</div>
                        <div className="text-[10px] text-slate-500 uppercase">{log.actor_role} • {log.ip_address}</div>
                      </td>
                      <td className="py-2.5 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                          isDenied
                            ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                            : log.action.includes('PERMISSION')
                            ? 'bg-purple-500/20 text-purple-300 border-purple-500/30'
                            : log.action.includes('DOWNLOAD')
                            ? 'bg-blue-500/20 text-blue-300 border-blue-500/30'
                            : 'bg-slate-800 text-slate-300 border-slate-700'
                        }`}>
                          {log.action}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 font-sans">
                        <div className="text-slate-200 font-medium truncate max-w-xs" title={log.target_name || log.target_id}>
                          {log.target_name || log.target_id || 'System'}
                        </div>
                        {log.details_json && (
                          <div className="text-[10px] text-slate-400 truncate max-w-xs font-mono" title={log.details_json}>
                            {log.details_json}
                          </div>
                        )}
                      </td>
                      <td className="py-2.5 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                          isDenied
                            ? 'bg-rose-500/20 text-rose-300 border-rose-500/30 flex items-center gap-1 w-fit'
                            : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                        }`}>
                          {isDenied && <AlertOctagon className="w-3 h-3 text-rose-400" />}
                          {log.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-[10px] text-slate-400" title={`HMAC-SHA256: ${log.record_hash}`}>
                        <span className="text-emerald-400/90">{log.record_hash.substring(0, 16)}...</span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
