import React, { useState } from 'react';
import { X, Upload, Sparkles, AlertCircle, FileCheck, ShieldAlert } from 'lucide-react';
import { api } from '../api/client';

interface UploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export const UploadModal: React.FC<UploadModalProps> = ({ isOpen, onClose, onSuccess }) => {
  const [file, setFile] = useState<File | null>(null);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [category, setCategory] = useState('Legal');
  const [classification, setClassification] = useState<'Confidential' | 'Restricted' | 'Internal' | 'Public'>('Confidential');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // AI Access Advisor state
  const [aiLoading, setAiLoading] = useState(false);
  const [aiSuggestion, setAiSuggestion] = useState<any>(null);

  if (!isOpen) return null;

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const selected = e.target.files[0];
      setFile(selected);
      if (!title) {
        setTitle(selected.name.replace(/\.[^/.]+$/, '').replace(/[_-]/g, ' '));
      }
    }
  };

  const handleAiAnalyze = async () => {
    if (!title) {
      setError('Please provide a document title first for AI risk classification.');
      return;
    }
    setError(null);
    setAiLoading(true);
    try {
      const res = await api.getAiRecommendation({
        documentTitle: title,
        category,
        description
      });
      setAiSuggestion(res.recommendation);
      if (res.recommendation.suggestedClassification) {
        setClassification(res.recommendation.suggestedClassification);
      }
    } catch (err: any) {
      setError(err.message || 'AI analysis failed');
    } finally {
      setAiLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) {
      setError('Please select a file to upload');
      return;
    }
    if (!title.trim()) {
      setError('Document title is required');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('title', title.trim());
      formData.append('description', description.trim());
      formData.append('category', category);
      formData.append('classification', classification);

      await api.uploadDocument(formData);
      onSuccess();
      onClose();
    } catch (err: any) {
      setError(err.message || 'Upload failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full overflow-hidden shadow-2xl animate-in fade-in zoom-in-95 duration-150">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/60">
          <div className="flex items-center gap-2">
            <Upload className="w-5 h-5 text-emerald-400" />
            <h2 className="text-base font-semibold text-white">Upload Secure Document</h2>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 transition p-1 rounded-md hover:bg-slate-800"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {error && (
            <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg flex items-start gap-2.5 text-xs text-rose-300">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {/* File input */}
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">Document File</label>
            <div className="border-2 border-dashed border-slate-700 hover:border-slate-600 rounded-lg p-4 text-center cursor-pointer transition bg-slate-950/30">
              <input
                type="file"
                onChange={handleFileChange}
                className="hidden"
                id="file-upload"
                accept=".pdf,.txt,.csv,.json,.png,.jpg,.jpeg,.docx,.xlsx"
              />
              <label htmlFor="file-upload" className="cursor-pointer block">
                {file ? (
                  <div className="flex items-center justify-center gap-2 text-emerald-400 text-sm">
                    <FileCheck className="w-5 h-5" />
                    <span className="font-medium text-slate-200">{file.name}</span>
                    <span className="text-xs text-slate-400">({(file.size / 1024).toFixed(1)} KB)</span>
                  </div>
                ) : (
                  <div>
                    <Upload className="w-8 h-8 text-slate-400 mx-auto mb-2" />
                    <span className="text-xs text-slate-300 font-medium">Click to select file</span>
                    <p className="text-[11px] text-slate-500 mt-1">
                      PDF, DOCX, XLSX, TXT, CSV, PNG, JPG (Max 25MB). Magic bytes verified.
                    </p>
                  </div>
                )}
              </label>
            </div>
          </div>

          {/* Title & Category */}
          <div className="grid grid-cols-2 gap-3">
            <div className="col-span-2">
              <label className="block text-xs font-medium text-slate-300 mb-1">Title</label>
              <input
                type="text"
                value={title}
                onChange={e => setTitle(e.target.value)}
                placeholder="e.g. Q3 Executive Compensation Review"
                required
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Category</label>
              <select
                value={category}
                onChange={e => setCategory(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
              >
                <option value="Legal">Legal</option>
                <option value="Financial">Financial</option>
                <option value="HR">HR / Compensation</option>
                <option value="Executive">Executive</option>
                <option value="Engineering">Engineering</option>
                <option value="Compliance">Compliance</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Classification</label>
              <select
                value={classification}
                onChange={e => setClassification(e.target.value as any)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
              >
                <option value="Confidential">Confidential (Default Deny)</option>
                <option value="Restricted">Restricted (Department)</option>
                <option value="Internal">Internal Only</option>
                <option value="Public">Public</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Description (Optional)</label>
            <textarea
              value={description}
              onChange={e => setDescription(e.target.value)}
              rows={2}
              placeholder="Context or purpose of this document..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
            />
          </div>

          {/* AI Access Advisor Trigger */}
          <div className="bg-emerald-950/20 border border-emerald-500/20 rounded-lg p-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-emerald-400" />
                <span className="text-xs font-medium text-emerald-300">AI Access Advisor</span>
              </div>
              <button
                type="button"
                onClick={handleAiAnalyze}
                disabled={aiLoading}
                className="px-2.5 py-1 text-xs bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/30 rounded font-medium transition flex items-center gap-1"
              >
                {aiLoading ? 'Analyzing...' : 'Scan Sensitivity'}
              </button>
            </div>

            {aiSuggestion && (
              <div className="mt-2.5 pt-2 border-t border-emerald-500/20 text-xs space-y-1.5">
                <div className="flex items-center gap-2">
                  <span className="text-slate-400">Recommended:</span>
                  <span className="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-semibold text-[10px]">
                    {aiSuggestion.suggestedClassification}
                  </span>
                  <span className="text-[11px] text-slate-400">
                    Risk: <strong className="text-amber-400">{aiSuggestion.riskAssessment?.dataSensitivityLevel}</strong>
                  </span>
                </div>
                <p className="text-slate-300 text-[11px] leading-relaxed">
                  {aiSuggestion.securityRationale}
                </p>
                <div className="text-[10px] text-slate-400 italic">
                  *AI never expands access automatically. You will confirm specific recipients in the permissions manager after upload.
                </div>
              </div>
            )}
          </div>

          <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg text-sm font-medium text-slate-300 hover:bg-slate-800 transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading || !file}
              className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition shadow-sm shadow-emerald-600/30 flex items-center gap-2"
            >
              {loading ? 'Encrypting & Storing...' : 'Upload & Encrypt'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
