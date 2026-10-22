const API_BASE = (import.meta.env.VITE_API_URL || '/api').replace(/\/$/, '');

function getAuthHeader(): Record<string, string> {
  const token = localStorage.getItem('trustvault_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export const api = {
  // Auth
  async login(email: string, password: string) {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Authentication failed');
    }
    return res.json();
  },

  async getMe() {
    const res = await fetch(`${API_BASE}/auth/me`, {
      headers: getAuthHeader()
    });
    if (!res.ok) throw new Error('Failed to fetch user');
    return res.json();
  },

  async listUsers() {
    const res = await fetch(`${API_BASE}/auth/users`, {
      headers: getAuthHeader()
    });
    if (!res.ok) throw new Error('Failed to list users');
    return res.json();
  },

  // Documents
  async listDocuments(params?: { q?: string; category?: string; fromDate?: string; toDate?: string }) {
    const searchParams = new URLSearchParams();
    if (params?.q) searchParams.set('q', params.q);
    if (params?.category) searchParams.set('category', params.category);
    if (params?.fromDate) searchParams.set('fromDate', params.fromDate);
    if (params?.toDate) searchParams.set('toDate', params.toDate);

    const res = await fetch(`${API_BASE}/documents?${searchParams.toString()}`, {
      headers: getAuthHeader()
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to list documents');
    }
    return res.json();
  },

  async getDocument(id: string) {
    const res = await fetch(`${API_BASE}/documents/${id}`, {
      headers: getAuthHeader()
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Access denied');
    }
    return res.json();
  },

  async uploadDocument(formData: FormData) {
    const headers = getAuthHeader();
    // Do not set Content-Type header so browser populates boundary
    const res = await fetch(`${API_BASE}/documents`, {
      method: 'POST',
      headers,
      body: formData
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Upload failed');
    }
    return res.json();
  },

  async updateDocument(id: string, formData: FormData) {
    const headers = getAuthHeader();
    const res = await fetch(`${API_BASE}/documents/${id}`, {
      method: 'PUT',
      headers,
      body: formData
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Update failed');
    }
    return res.json();
  },

  async deleteDocument(id: string) {
    const res = await fetch(`${API_BASE}/documents/${id}`, {
      method: 'DELETE',
      headers: getAuthHeader()
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Delete failed');
    }
    return res.json();
  },

  async downloadDocument(id: string, filename: string) {
    const res = await fetch(`${API_BASE}/documents/${id}/download`, {
      headers: getAuthHeader()
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Download failed: Access denied');
    }
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  },

  // Permissions
  async listPermissions(documentId: string) {
    const res = await fetch(`${API_BASE}/documents/${documentId}/permissions`, {
      headers: getAuthHeader()
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to list permissions');
    }
    return res.json();
  },

  async grantPermission(documentId: string, userId: string, permissionLevel: 'view' | 'edit') {
    const res = await fetch(`${API_BASE}/documents/${documentId}/permissions`, {
      method: 'POST',
      headers: { ...getAuthHeader(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId, permissionLevel })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to grant permission');
    }
    return res.json();
  },

  async revokePermission(documentId: string, userId: string) {
    const res = await fetch(`${API_BASE}/documents/${documentId}/permissions/${userId}`, {
      method: 'DELETE',
      headers: getAuthHeader()
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to revoke permission');
    }
    return res.json();
  },

  // Audit
  async getAuditLogs(params?: { action?: string; status?: string; documentId?: string }) {
    const searchParams = new URLSearchParams();
    if (params?.action) searchParams.set('action', params.action);
    if (params?.status) searchParams.set('status', params.status);
    if (params?.documentId) searchParams.set('documentId', params.documentId);

    const res = await fetch(`${API_BASE}/audit?${searchParams.toString()}`, {
      headers: getAuthHeader()
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to fetch audit logs');
    }
    return res.json();
  },

  async verifyAuditChain() {
    const res = await fetch(`${API_BASE}/audit/verify`, {
      headers: getAuthHeader()
    });
    if (!res.ok) throw new Error('Verification request failed');
    return res.json();
  },

  // Admin
  async getSecurityAlerts() {
    const res = await fetch(`${API_BASE}/admin/alerts`, {
      headers: getAuthHeader()
    });
    if (!res.ok) throw new Error('Failed to fetch security alerts');
    return res.json();
  },

  async getAdminMetrics() {
    const res = await fetch(`${API_BASE}/admin/metrics`, {
      headers: getAuthHeader()
    });
    if (!res.ok) throw new Error('Failed to fetch admin metrics');
    return res.json();
  },

  async toggleUserStatus(userId: string) {
    const res = await fetch(`${API_BASE}/admin/users/${userId}/toggle`, {
      method: 'POST',
      headers: getAuthHeader()
    });
    if (!res.ok) throw new Error('Failed to toggle user status');
    return res.json();
  },

  // AI Advisory
  async getAiRecommendation(data: { documentTitle: string; category: string; description?: string; documentId?: string }) {
    const res = await fetch(`${API_BASE}/ai/recommend`, {
      method: 'POST',
      headers: { ...getAuthHeader(), 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error('Failed to generate recommendation');
    return res.json();
  },

  async confirmAiDecision(data: {
    documentId: string;
    advisoryId: string;
    decision: 'ACCEPTED' | 'REJECTED' | 'MODIFIED';
    confirmedGrants: Array<{ userId: string; permissionLevel: 'view' | 'edit' }>;
  }) {
    const res = await fetch(`${API_BASE}/ai/confirm`, {
      method: 'POST',
      headers: { ...getAuthHeader(), 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error('Failed to confirm decision');
    return res.json();
  }
};
