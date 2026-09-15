import React from 'react';
import { Shield, Network } from 'lucide-react';

export default function Navbar({ activeFile }) {
  return (
    <nav className="glass-panel border-b border-gray-800/80 sticky top-0 z-40 px-6 py-3">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        {/* Brand Logo */}
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400 glow-blue">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-extrabold text-xl tracking-tight text-white">NetIntel NOC</span>
              <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/20 text-blue-400 border border-blue-500/30 font-semibold">
                Network Analysis
              </span>
            </div>
            <p className="text-[10px] text-gray-400 tracking-wider uppercase">Real Packet Inspection & Anomaly Platform</p>
          </div>
        </div>

        {/* Header Active File Indicator */}
        <div className="flex items-center space-x-3">
          {activeFile ? (
            <div className="flex items-center space-x-2 px-3.5 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-xs font-mono text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              <span>Loaded: {activeFile}</span>
            </div>
          ) : (
            <div className="flex items-center space-x-2 px-3.5 py-1.5 rounded-full bg-gray-900 border border-gray-800 text-xs text-gray-400">
              <Network className="w-3.5 h-3.5 text-blue-400" />
              <span>Ready for PCAP Upload</span>
            </div>
          )}
        </div>
      </div>
    </nav>
  );
}

