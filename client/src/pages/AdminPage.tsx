import React, { useState, useEffect } from 'react';
import { ShieldAlert, Users, HardDrive, AlertTriangle, ShieldCheck, UserX, UserCheck, Activity } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';

export const AdminPage: React.FC = () => {
  const { user } = useAuth();
  const [alerts, setAlerts] = useState<any[]>([]);
  const [metrics, setMetrics] = useState<any>(null);
  const [usersList, setUsersList] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadAdminData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [alertsRes, metricsRes, usersRes] = await Promise.all([
        api.getSecurityAlerts(),
        api.getAdminMetrics(),
        api.listUsers()
      ]);
      setAlerts(alertsRes.alerts || []);
      setMetrics(metricsRes.metrics || null);
      setUsersList(usersRes.users || []);
    } catch (err: any) {
      setError(err.message || 'Failed to load security telemetry');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAdminData();
  }, [user]);

  const handleToggleUser = async (targetUser: any) => {
    try {
      await api.toggleUserStatus(targetUser.id);
      loadAdminData();
    } catch (err: any) {
      alert(`User status toggle failed: ${err.message}`);
    }
  };

  if (user?.role !== 'admin') {
    return (
      <div className="max-w-4xl mx-auto px-4 py-16 text-center space-y-4">
        <ShieldAlert className="w-12 h-12 text-rose-400 mx-auto" />
        <h2 className="text-lg font-bold text-white">Administrator Access Required</h2>
        <p className="text-xs text-slate-400 max-w-md mx-auto">
          Please use the Fast Persona Switcher in the top bar to switch to <strong>Audit Administrator (admin@trustvault.internal)</strong> to view security alerts and operational telemetry.
        </p>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Security Telemetry & Operations</h1>
        <p className="text-sm text-slate-400 mt-1">
          Administrative oversight of access violations, threat anomalies, and user session lifecycles.
        </p>
      </div>

      {/* Metrics Row */}
      {metrics && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-xs font-semibold uppercase">Total Vault Documents</span>
              <HardDrive className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="text-2xl font-bold text-white mt-2 font-mono">
              {metrics.documents?.total_documents || 0}
            </div>
            <div className="text-[11px] text-slate-500 mt-1 font-mono">
              {((metrics.documents?.total_storage_bytes || 0) / 1024).toFixed(1)} KB encrypted storage
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-xs font-semibold uppercase">Refused Probes</span>
              <ShieldAlert className="w-4 h-4 text-rose-400" />
            </div>
            <div className="text-2xl font-bold text-rose-400 mt-2 font-mono">
              {metrics.audit?.total_denied_events || 0}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">
              Unauthorized access attempts intercepted
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-xs font-semibold uppercase">Chained Audit Events</span>
              <Activity className="w-4 h-4 text-blue-400" />
            </div>
            <div className="text-2xl font-bold text-white mt-2 font-mono">
              {metrics.audit?.total_audit_records || 0}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">
              {metrics.audit?.total_downloads || 0} downloads • {metrics.audit?.total_uploads || 0} uploads
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-xs font-semibold uppercase">Active Users</span>
              <Users className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-white mt-2 font-mono">
              {metrics.users?.active_users || 0} / {metrics.users?.total_users || 0}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">
              Role-based zero-trust accounts
            </div>
          </div>
        </div>
      )}

      {/* Security Alerts Section */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-amber-400" />
            <h2 className="text-base font-semibold text-white">Automated Security Anomaly Alerts</h2>
          </div>
          <span className="text-xs px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 font-mono">
            {alerts.length} Detected
          </span>
        </div>

        {alerts.length === 0 ? (
          <div className="p-6 bg-slate-950/40 rounded-lg text-center text-xs text-slate-500">
            No active threat anomalies detected. Zero-trust access controls functioning nominally.
          </div>
        ) : (
          <div className="space-y-2.5">
            {alerts.map((alert, idx) => (
              <div
                key={idx}
                className="p-3.5 bg-slate-950/60 border border-slate-800 rounded-lg flex items-start justify-between gap-3"
              >
                <div className="flex items-start gap-3">
                  <div className={`p-1.5 rounded ${
                    alert.severity === 'HIGH' ? 'bg-rose-500/20 text-rose-400' : 'bg-amber-500/20 text-amber-400'
                  }`}>
                    <ShieldAlert className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold text-white">{alert.title}</span>
                      <span className={`text-[10px] font-mono font-bold uppercase px-1.5 py-0.2 rounded border ${
                        alert.severity === 'HIGH'
                          ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                          : 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                      }`}>
                        {alert.severity}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-0.5 leading-relaxed">{alert.description}</p>
                    <span className="text-[10px] text-slate-500 font-mono mt-1 block">
                      Last detected: {new Date(alert.lastDetected).toLocaleString()}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* User Management & Immediate Account Deactivation */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Users className="w-5 h-5 text-emerald-400" />
            <h2 className="text-base font-semibold text-white">User Accounts & Immediate Revocation Controls</h2>
          </div>
          <span className="text-xs text-slate-400">
            Deactivating an account immediately invalidates all existing sessions.
          </span>
        </div>

        <div className="border border-slate-800 rounded-lg overflow-hidden divide-y divide-slate-800">
          {usersList.map(u => (
            <div key={u.id} className="p-3 bg-slate-950/40 flex items-center justify-between">
              <div>
                <div className="text-xs font-medium text-slate-200">{u.name}</div>
                <div className="text-[11px] text-slate-400 font-mono">{u.email} • Role: {u.role}</div>
              </div>

              <div className="flex items-center gap-3">
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-semibold ${
                  u.is_active === 1 ? 'bg-emerald-500/20 text-emerald-300' : 'bg-rose-500/20 text-rose-300'
                }`}>
                  {u.is_active === 1 ? 'Active' : 'Deactivated'}
                </span>

                <button
                  onClick={() => handleToggleUser(u)}
                  className={`px-3 py-1 text-xs font-medium rounded transition flex items-center gap-1.5 ${
                    u.is_active === 1
                      ? 'bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border border-rose-500/30'
                      : 'bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30'
                  }`}
                >
                  {u.is_active === 1 ? (
                    <>
                      <UserX className="w-3.5 h-3.5" />
                      <span>Deactivate</span>
                    </>
                  ) : (
                    <>
                      <UserCheck className="w-3.5 h-3.5" />
                      <span>Activate</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
