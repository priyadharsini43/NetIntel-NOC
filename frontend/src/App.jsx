import React, { useState } from 'react';
import { Upload, FileSpreadsheet, FileCode, FileText, AlertTriangle, Activity, Server, Radio, ArrowUpRight } from 'lucide-react';
import axios from 'axios';

import Navbar from './components/Navbar';
import NetworkTopology from './components/NetworkTopology';
import PacketSearchFilter from './components/PacketSearchFilter';
import PacketModal from './components/PacketModal';

export default function App() {
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisData, setAnalysisData] = useState(null);
  const [error, setError] = useState('');
  const [activePacket, setActivePacket] = useState(null);

  const handleFileUpload = async (selectedFile) => {
    if (!selectedFile) return;
    setError('');
    setAnalyzing(true);
    setAnalysisData(null);

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      // 1. Upload PCAP file
      const uploadRes = await axios.post('/upload', formData);
      const filename = uploadRes.data.filename;

      // 2. Analyze PCAP file
      const analyzeRes = await axios.get(`/analyze/${encodeURIComponent(filename)}`);
      setAnalysisData(analyzeRes.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to parse or analyze the uploaded PCAP file.');
    } finally {
      setAnalyzing(false);
    }
  };

  const summary = analysisData?.summary;
  const proto = analysisData?.protocol_distribution;
  const topComms = analysisData?.top_communications || [];
  const topology = analysisData?.topology;
  const anomalies = analysisData?.anomalies || [];
  const packets = analysisData?.packets || [];

  return (
    <div className="min-h-screen flex flex-col bg-[#080c14] text-gray-100 selection:bg-blue-600 selection:text-white">
      {/* Header Navbar */}
      <Navbar activeFile={summary?.filename} />

      {/* Content Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">
        {/* Upload Zone */}
        <div className="glass-panel p-8 rounded-2xl border border-gray-800 text-center space-y-4">
          <div className="w-14 h-14 rounded-2xl bg-blue-600/20 border border-blue-500/40 text-blue-400 flex items-center justify-center mx-auto glow-blue">
            <Upload className="w-7 h-7" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">Upload PCAP / PCAPNG Network Capture</h2>
            <p className="text-xs text-gray-400 mt-1">
              Select or drop a recorded network packet capture file (.pcap, .cap, .pcapng) for Scapy parsing & rule-based anomaly detection.
            </p>
          </div>

          <div className="max-w-md mx-auto relative border-2 border-dashed border-gray-700 hover:border-blue-500/60 rounded-2xl p-6 transition-all bg-gray-900/40">
            <input
              type="file"
              accept=".pcap,.cap,.pcapng"
              onChange={(e) => e.target.files?.[0] && handleFileUpload(e.target.files[0])}
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
            />
            <p className="text-xs font-semibold text-gray-300">Drag & Drop PCAP file here</p>
            <p className="text-[11px] text-gray-500 mt-1">or click to select file from your computer</p>
          </div>

          {analyzing && (
            <div className="flex items-center justify-center space-x-3 text-blue-400 text-xs font-semibold py-2">
              <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-500"></div>
              <span>Parsing packet headers with Scapy & running anomaly detection rules...</span>
            </div>
          )}

          {error && (
            <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-xs max-w-md mx-auto">
              {error}
            </div>
          )}
        </div>

        {/* Dashboard Results */}
        {analysisData && (
          <div className="space-y-6 animate-in fade-in duration-300">
            {/* Action Bar / Export Buttons */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 glass-panel p-5 rounded-2xl border border-gray-800">
              <div>
                <span className="text-xs text-gray-400 uppercase font-semibold">Analyzed File</span>
                <h3 className="text-base font-mono font-bold text-white">{summary.filename}</h3>
              </div>

              <div className="flex items-center space-x-2">
                <a
                  href={`/export/csv/${encodeURIComponent(summary.filename)}`}
                  className="flex items-center space-x-1.5 text-xs bg-gray-900 hover:bg-gray-800 text-emerald-400 border border-emerald-500/30 font-bold px-3.5 py-2 rounded-xl transition-all"
                >
                  <FileSpreadsheet className="w-4 h-4" />
                  <span>Export CSV</span>
                </a>

                <a
                  href={`/export/json/${encodeURIComponent(summary.filename)}`}
                  className="flex items-center space-x-1.5 text-xs bg-gray-900 hover:bg-gray-800 text-amber-400 border border-amber-500/30 font-bold px-3.5 py-2 rounded-xl transition-all"
                >
                  <FileCode className="w-4 h-4" />
                  <span>Export JSON</span>
                </a>

                <a
                  href={`/export/pdf/${encodeURIComponent(summary.filename)}`}
                  className="flex items-center space-x-1.5 text-xs bg-blue-600 hover:bg-blue-500 text-white font-bold px-4 py-2 rounded-xl transition-all shadow-md glow-blue"
                >
                  <FileText className="w-4 h-4" />
                  <span>Export PDF Report</span>
                </a>
              </div>
            </div>

            {/* Summary Metrics Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
              <div className="glass-panel p-4 rounded-xl border border-gray-800 space-y-1">
                <div className="flex items-center justify-between text-xs text-gray-400">
                  <span>Total Packets</span>
                  <Activity className="w-4 h-4 text-blue-400" />
                </div>
                <p className="text-2xl font-mono font-bold text-white">{summary.total_packets.toLocaleString()}</p>
              </div>

              <div className="glass-panel p-4 rounded-xl border border-gray-800 space-y-1">
                <div className="flex items-center justify-between text-xs text-gray-400">
                  <span>Total Volume</span>
                  <Radio className="w-4 h-4 text-emerald-400" />
                </div>
                <p className="text-2xl font-mono font-bold text-emerald-400">{summary.total_bytes.toLocaleString()} <span className="text-xs font-normal">B</span></p>
              </div>

              <div className="glass-panel p-4 rounded-xl border border-gray-800 space-y-1">
                <div className="flex items-center justify-between text-xs text-gray-400">
                  <span>Unique Hosts</span>
                  <Server className="w-4 h-4 text-purple-400" />
                </div>
                <p className="text-2xl font-mono font-bold text-purple-400">{summary.unique_hosts}</p>
              </div>

              <div className="glass-panel p-4 rounded-xl border border-gray-800 space-y-1">
                <div className="flex items-center justify-between text-xs text-gray-400">
                  <span>Rule-Based Alerts</span>
                  <AlertTriangle className={`w-4 h-4 ${summary.anomaly_count > 0 ? 'text-red-400' : 'text-emerald-400'}`} />
                </div>
                <p className={`text-2xl font-mono font-bold ${summary.anomaly_count > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                  {summary.anomaly_count}
                </p>
              </div>
            </div>

            {/* Primary Security Classifier: ML NIDS Section */}
            {analysisData?.ml_prediction && analysisData.ml_prediction.model_available && (
              <div className="glass-panel p-6 rounded-2xl border border-gray-800 space-y-4">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div className="flex items-center space-x-3">
                    <div className={`p-3 rounded-xl ${analysisData.ml_prediction.status === 'ATTACK' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'}`}>
                      <Activity className="w-6 h-6" />
                    </div>
                    <div>
                      <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Primary Security Classifier — ML NIDS</span>
                      <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                        <span>Traffic Classification:</span>
                        <span className={`px-2.5 py-0.5 rounded font-mono font-bold text-sm ${analysisData.ml_prediction.status === 'ATTACK' ? 'bg-red-500/30 text-red-300' : 'bg-emerald-500/30 text-emerald-300'}`}>
                          {analysisData.ml_prediction.status}
                        </span>
                      </h3>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-6 text-xs border-t md:border-t-0 md:border-l border-gray-800 pt-3 md:pt-0 md:pl-6">
                    {analysisData.ml_prediction.status === 'ATTACK' && analysisData.ml_prediction.attack_type && (
                      <div>
                        <span className="text-gray-400 block font-medium">Detected Attack Type</span>
                        <span className="text-red-400 font-bold font-mono text-sm">{analysisData.ml_prediction.attack_type}</span>
                      </div>
                    )}
                    <div>
                      <span className="text-gray-400 block font-medium">Model Probability</span>
                      <span className="text-blue-400 font-bold font-mono text-sm">{analysisData.ml_prediction.confidence}%</span>
                    </div>
                    <div>
                      <span className="text-gray-400 block font-medium">Flows Classified</span>
                      <span className="text-white font-bold font-mono text-sm">{analysisData.ml_prediction.evaluated_flows}</span>
                    </div>
                  </div>
                </div>

                <div className="text-[11px] text-gray-400 bg-gray-900/60 p-3 rounded-xl border border-gray-800 flex items-center justify-between flex-wrap gap-2">
                  <span>
                    <strong className="text-gray-300">Model:</strong> RandomForestClassifier &nbsp;|&nbsp;
                    <strong className="text-gray-300"> Provenance:</strong> Genuine CIC-IDS2017 dataset &nbsp;|&nbsp;
                    <strong className="text-gray-300"> Classes:</strong> {analysisData.ml_prediction.supported_classes?.join(', ')}
                  </span>
                  {analysisData.ml_prediction.evaluation_metrics?.multiclass_metrics?.accuracy && (
                    <span className="text-emerald-400 font-semibold">
                      Unseen Test Accuracy: {(analysisData.ml_prediction.evaluation_metrics.multiclass_metrics.accuracy * 100).toFixed(2)}% | FPR: {analysisData.ml_prediction.evaluation_metrics.binary_cybersecurity_metrics?.false_positive_rate_percent}
                    </span>
                  )}
                </div>
              </div>
            )}

            {/* Middle Row: Protocol Distribution & Top Communications */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Protocol Breakdown Card */}
              <div className="glass-panel p-6 rounded-2xl border border-gray-800 space-y-4">
                <h3 className="text-sm font-bold text-white flex items-center space-x-2">
                  <Activity className="w-4 h-4 text-blue-400" />
                  <span>Actual Protocol Distribution</span>
                </h3>

                <div className="space-y-3 text-xs">
                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-gray-300 font-semibold">TCP</span>
                      <span className="text-gray-400 font-mono">{proto?.tcp_count} ({proto?.tcp_percentage}%)</span>
                    </div>
                    <div className="w-full h-2 bg-gray-900 rounded-full overflow-hidden">
                      <div className="h-full bg-blue-500 rounded-full" style={{ width: `${proto?.tcp_percentage}%` }}></div>
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-gray-300 font-semibold">UDP</span>
                      <span className="text-gray-400 font-mono">{proto?.udp_count} ({proto?.udp_percentage}%)</span>
                    </div>
                    <div className="w-full h-2 bg-gray-900 rounded-full overflow-hidden">
                      <div className="h-full bg-purple-500 rounded-full" style={{ width: `${proto?.udp_percentage}%` }}></div>
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-gray-300 font-semibold">ICMP</span>
                      <span className="text-gray-400 font-mono">{proto?.icmp_count} ({proto?.icmp_percentage}%)</span>
                    </div>
                    <div className="w-full h-2 bg-gray-900 rounded-full overflow-hidden">
                      <div className="h-full bg-amber-500 rounded-full" style={{ width: `${proto?.icmp_percentage}%` }}></div>
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-gray-300 font-semibold">Other</span>
                      <span className="text-gray-400 font-mono">{proto?.other_count} ({proto?.other_percentage}%)</span>
                    </div>
                    <div className="w-full h-2 bg-gray-900 rounded-full overflow-hidden">
                      <div className="h-full bg-gray-600 rounded-full" style={{ width: `${proto?.other_percentage}%` }}></div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Top Communications Card */}
              <div className="glass-panel p-6 rounded-2xl border border-gray-800 space-y-4">
                <h3 className="text-sm font-bold text-white flex items-center space-x-2">
                  <ArrowUpRight className="w-4 h-4 text-emerald-400" />
                  <span>Top Communicating Hosts</span>
                </h3>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-gray-900 text-gray-400 uppercase text-[10px] font-bold border-b border-gray-800">
                      <tr>
                        <th className="px-3 py-2">Source IP</th>
                        <th className="px-3 py-2">Destination IP</th>
                        <th className="px-3 py-2 text-right">Packets</th>
                        <th className="px-3 py-2 text-right">Bytes</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800 font-mono">
                      {topComms.slice(0, 5).map((comm, idx) => (
                        <tr key={idx} className="hover:bg-gray-800/40">
                          <td className="px-3 py-2 text-white">{comm.src_ip}</td>
                          <td className="px-3 py-2 text-blue-400">{comm.dst_ip}</td>
                          <td className="px-3 py-2 text-right text-emerald-400 font-bold">{comm.packets}</td>
                          <td className="px-3 py-2 text-right text-gray-400">{comm.bytes.toLocaleString()} B</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            {/* Network Topology Graph */}
            <NetworkTopology topology={topology} />

            {/* Rule-Based Alerts List */}
            {anomalies.length > 0 ? (
              <div className="glass-panel p-6 rounded-2xl border border-gray-800 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold text-white flex items-center space-x-2">
                    <AlertTriangle className="w-4 h-4 text-red-400" />
                    <span>Rule-Based Alerts & Suspicious Traffic Patterns ({anomalies.length})</span>
                  </h3>
                  <span className="text-[11px] text-gray-400">Secondary Supporting Indicators</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  {anomalies.map((anom) => (
                    <div key={anom.id} className="p-4 rounded-xl bg-red-950/20 border border-red-500/30 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-white text-xs">{anom.reason}</span>
                        <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                          anom.severity === 'HIGH' ? 'bg-red-500/30 text-red-300' : 'bg-amber-500/30 text-amber-300'
                        }`}>
                          {anom.severity}
                        </span>
                      </div>
                      <p className="font-mono text-gray-300">
                        Source IP: <span className="text-white font-bold">{anom.src_ip}</span>
                        {anom.dst_ip !== '*' && <span> → Destination: <span className="text-white font-bold">{anom.dst_ip}</span></span>}
                      </p>
                      <div className="text-gray-400 space-y-0.5 text-[11px]">
                        <p>Observed: <span className="text-red-300 font-semibold">{anom.observed_value}</span></p>
                        <p>Configured Threshold: <span className="text-gray-300">{anom.threshold}</span></p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="glass-panel p-6 rounded-2xl border border-gray-800 text-center text-xs text-gray-400">
                <span className="text-emerald-400 font-bold">No Rule Anomalies Detected:</span> Traffic behavior matches configured normal baseline rules.
              </div>
            )}

            {/* Packet Search & Filter Table */}
            <PacketSearchFilter packets={packets} onSelectPacket={(pkt) => setActivePacket(pkt)} />
          </div>
        )}
      </main>

      {/* Frame Inspector Modal */}
      {activePacket && (
        <PacketModal packet={activePacket} onClose={() => setActivePacket(null)} />
      )}
    </div>
  );
}

