import React from 'react';
import { X, Network, Clock, ShieldCheck, Activity } from 'lucide-react';

export default function PacketModal({ packet, onClose }) {
  if (!packet) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="glass-panel w-full max-w-xl rounded-2xl border border-gray-800 p-6 space-y-6 animate-in fade-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-gray-800 pb-4">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-blue-500/20 text-blue-400 border border-blue-500/30">
              <Network className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">
                Frame Metadata Inspector #{packet.packet_id}
              </h3>
              <p className="text-xs text-gray-400 font-mono">
                Timestamp: {packet.timestamp || 'N/A'}
              </p>
            </div>
          </div>

          <button 
            onClick={onClose}
            className="text-gray-400 hover:text-white p-2 rounded-lg hover:bg-gray-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Packet Fields Grid */}
        <div className="grid grid-cols-2 gap-4 text-xs">
          <div className="p-3.5 rounded-xl bg-gray-900/60 border border-gray-800 space-y-1">
            <span className="text-gray-500 uppercase font-semibold text-[10px]">Source Endpoint</span>
            <p className="font-mono text-white text-sm">{packet.src_ip}:{packet.src_port || '*'}</p>
          </div>

          <div className="p-3.5 rounded-xl bg-gray-900/60 border border-gray-800 space-y-1">
            <span className="text-gray-500 uppercase font-semibold text-[10px]">Destination Endpoint</span>
            <p className="font-mono text-white text-sm">{packet.dst_ip}:{packet.dst_port || '*'}</p>
          </div>

          <div className="p-3.5 rounded-xl bg-gray-900/60 border border-gray-800 space-y-1">
            <span className="text-gray-500 uppercase font-semibold text-[10px]">Protocol Layer</span>
            <p className="font-mono text-blue-400 font-bold text-sm">
              {packet.protocol} {packet.protocol_num ? `(${packet.protocol_num})` : ''}
            </p>
          </div>

          <div className="p-3.5 rounded-xl bg-gray-900/60 border border-gray-800 space-y-1">
            <span className="text-gray-500 uppercase font-semibold text-[10px]">Packet Length</span>
            <p className="font-mono text-emerald-400 font-bold text-sm">
              {packet.length} bytes
            </p>
          </div>
        </div>

        {/* TCP Flags */}
        {packet.protocol === 'TCP' && (
          <div className="p-3.5 rounded-xl bg-gray-900/60 border border-gray-800 text-xs">
            <span className="text-gray-500 uppercase font-semibold text-[10px] block mb-1">TCP Control Flags</span>
            <span className="text-amber-300 font-mono font-bold bg-amber-500/10 px-2.5 py-1 rounded border border-amber-500/20 inline-block">
              {packet.tcp_flags || 'NONE'}
            </span>
          </div>
        )}

        <div className="flex justify-end">
          <button 
            onClick={onClose}
            className="px-5 py-2 rounded-xl bg-gray-800 hover:bg-gray-700 text-white text-xs font-semibold transition-colors"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
}

