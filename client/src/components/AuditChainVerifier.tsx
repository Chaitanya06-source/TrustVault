import React, { useState, useEffect } from 'react';
import { ShieldCheck, ShieldAlert, RefreshCw, KeyRound, CheckCircle2, AlertTriangle } from 'lucide-react';
import { api } from '../api/client';

export const AuditChainVerifier: React.FC = () => {
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runVerification = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.verifyAuditChain();
      setResult(data.verification);
    } catch (err: any) {
      setError(err.message || 'Verification failed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    runVerification();
  }, []);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-emerald-500/10 border border-emerald-500/30 rounded-lg">
            <KeyRound className="w-5 h-5 text-emerald-400" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white">Cryptographic Tamper-Evident Audit Ledger</h3>
            <p className="text-xs text-slate-400">
              HMAC-SHA256 sequential hash chaining binds every access and refusal into an immutable chain.
            </p>
          </div>
        </div>

        <button
          onClick={runVerification}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded-lg text-xs font-medium transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-emerald-400' : ''}`} />
          <span>{loading ? 'Verifying Chain...' : 'Recalculate & Verify Ledger'}</span>
        </button>
      </div>

      {error && (
        <div className="mt-4 p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-xs text-rose-300 flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {result && (
        <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-3">
          {/* Status Box */}
          <div className={`p-4 rounded-lg border ${
            result.valid
              ? 'bg-emerald-950/20 border-emerald-500/30 text-emerald-300'
              : 'bg-rose-950/30 border-rose-500/40 text-rose-300'
          }`}>
            <div className="flex items-center gap-2 mb-1">
              {result.valid ? (
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
              ) : (
                <ShieldAlert className="w-5 h-5 text-rose-400" />
              )}
              <span className="font-semibold text-xs uppercase tracking-wider">
                {result.valid ? 'Chain Status: Pristine' : 'Chain Tampering Detected!'}
              </span>
            </div>
            <p className="text-[11px] opacity-90">
              {result.valid
                ? `100% verified across all ${result.totalRecords} contiguous audit blocks.`
                : result.failureReason}
            </p>
          </div>

          {/* Block Count */}
          <div className="p-4 rounded-lg bg-slate-950/50 border border-slate-800">
            <div className="text-[11px] text-slate-400 uppercase tracking-wider font-medium">Total Chained Blocks</div>
            <div className="text-xl font-bold text-white mt-1 font-mono">{result.totalRecords}</div>
            <div className="text-[10px] text-slate-500 mt-1">Every download, view, and refusal recorded</div>
          </div>

          {/* Latest Hash */}
          <div className="p-4 rounded-lg bg-slate-950/50 border border-slate-800 overflow-hidden">
            <div className="text-[11px] text-slate-400 uppercase tracking-wider font-medium">Latest Cryptographic Head</div>
            <div className="text-xs text-emerald-400 font-mono mt-1.5 truncate" title={result.latestHash}>
              {result.latestHash ? result.latestHash : 'Genesis Block'}
            </div>
            <div className="text-[10px] text-slate-500 mt-1">HMAC-SHA256 verified at {new Date(result.verifiedAt).toLocaleTimeString()}</div>
          </div>
        </div>
      )}
    </div>
  );
};
