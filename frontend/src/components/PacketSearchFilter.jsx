import React, { useState, useMemo } from 'react';
import { Search, Filter, RefreshCw, Eye } from 'lucide-react';

export default function PacketSearchFilter({ packets, onSelectPacket }) {
  const [srcIpFilter, setSrcIpFilter] = useState('');
  const [dstIpFilter, setDstIpFilter] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [portFilter, setPortFilter] = useState('');

  const filteredPackets = useMemo(() => {
    if (!packets) return [];
    return packets.filter((pkt) => {
      const matchSrc = !srcIpFilter || pkt.src_ip.toLowerCase().includes(srcIpFilter.toLowerCase());
      const matchDst = !dstIpFilter || pkt.dst_ip.toLowerCase().includes(dstIpFilter.toLowerCase());
      const matchProto = protocolFilter === 'ALL' || pkt.protocol === protocolFilter;
      const matchPort = !portFilter || String(pkt.src_port).includes(portFilter) || String(pkt.dst_port).includes(portFilter);

      return matchSrc && matchDst && matchProto && matchPort;
    });
  }, [packets, srcIpFilter, dstIpFilter, protocolFilter, portFilter]);

  const resetFilters = () => {
    setSrcIpFilter('');
    setDstIpFilter('');
    setProtocolFilter('ALL');
    setPortFilter('');
  };

  return (
    <div className="glass-panel p-6 rounded-2xl border border-gray-800 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-bold text-white flex items-center space-x-2">
            <Search className="w-4 h-4 text-blue-400" />
            <span>Real Packet Search & Filtering</span>
          </h3>
          <p className="text-xs text-gray-400 mt-0.5">
            Showing {filteredPackets.length} of {packets?.length || 0} parsed frame records
          </p>
        </div>

        <button
          onClick={resetFilters}
          className="text-xs text-gray-400 hover:text-white flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-800 self-start sm:self-auto"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Reset Filters</span>
        </button>
      </div>

      {/* Filter Controls Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs">
        <div>
          <label className="text-[10px] uppercase font-bold text-gray-500 block mb-1">Source IP</label>
          <input
            type="text"
            placeholder="e.g. 192.168.1.100"
            value={srcIpFilter}
            onChange={(e) => setSrcIpFilter(e.target.value)}
            className="w-full bg-gray-900 border border-gray-800 rounded-xl px-3 py-2 text-white font-mono placeholder:text-gray-600 focus:outline-none focus:border-blue-500/50"
          />
        </div>

        <div>
          <label className="text-[10px] uppercase font-bold text-gray-500 block mb-1">Destination IP</label>
          <input
            type="text"
            placeholder="e.g. 10.0.0.1"
            value={dstIpFilter}
            onChange={(e) => setDstIpFilter(e.target.value)}
            className="w-full bg-gray-900 border border-gray-800 rounded-xl px-3 py-2 text-white font-mono placeholder:text-gray-600 focus:outline-none focus:border-blue-500/50"
          />
        </div>

        <div>
          <label className="text-[10px] uppercase font-bold text-gray-500 block mb-1">Protocol</label>
          <select
            value={protocolFilter}
            onChange={(e) => setProtocolFilter(e.target.value)}
            className="w-full bg-gray-900 border border-gray-800 rounded-xl px-3 py-2 text-white font-semibold focus:outline-none focus:border-blue-500/50"
          >
            <option value="ALL">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
            <option value="OTHER">Other</option>
          </select>
        </div>

        <div>
          <label className="text-[10px] uppercase font-bold text-gray-500 block mb-1">Port Number</label>
          <input
            type="text"
            placeholder="e.g. 80, 443"
            value={portFilter}
            onChange={(e) => setPortFilter(e.target.value)}
            className="w-full bg-gray-900 border border-gray-800 rounded-xl px-3 py-2 text-white font-mono placeholder:text-gray-600 focus:outline-none focus:border-blue-500/50"
          />
        </div>
      </div>

      {/* Packet Table */}
      <div className="overflow-x-auto border border-gray-800 rounded-xl">
        <table className="w-full text-left text-xs">
          <thead className="bg-gray-900/80 text-gray-400 uppercase text-[10px] font-bold border-b border-gray-800">
            <tr>
              <th className="px-4 py-3">ID</th>
              <th className="px-4 py-3">Time</th>
              <th className="px-4 py-3">Source Endpoint</th>
              <th className="px-4 py-3">Destination Endpoint</th>
              <th className="px-4 py-3">Protocol</th>
              <th className="px-4 py-3">Length</th>
              <th className="px-4 py-3 text-right">Inspect</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/60 font-mono">
            {filteredPackets.slice(0, 100).map((pkt) => (
              <tr key={pkt.packet_id} className="hover:bg-gray-800/40 transition-colors">
                <td className="px-4 py-2.5 text-gray-500">#{pkt.packet_id}</td>
                <td className="px-4 py-2.5 text-gray-400">{pkt.timestamp}</td>
                <td className="px-4 py-2.5 text-white">{pkt.src_ip}:{pkt.src_port || '*'}</td>
                <td className="px-4 py-2.5 text-white">{pkt.dst_ip}:{pkt.dst_port || '*'}</td>
                <td className="px-4 py-2.5">
                  <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                    pkt.protocol === 'TCP' ? 'bg-blue-500/20 text-blue-400' :
                    pkt.protocol === 'UDP' ? 'bg-purple-500/20 text-purple-400' :
                    pkt.protocol === 'ICMP' ? 'bg-amber-500/20 text-amber-400' : 'bg-gray-800 text-gray-400'
                  }`}>
                    {pkt.protocol}
                  </span>
                </td>
                <td className="px-4 py-2.5 text-gray-300">{pkt.length} B</td>
                <td className="px-4 py-2.5 text-right">
                  <button
                    onClick={() => onSelectPacket(pkt)}
                    className="p-1 rounded bg-gray-800 hover:bg-blue-600 text-gray-300 hover:text-white transition-colors"
                  >
                    <Eye className="w-3.5 h-3.5" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filteredPackets.length === 0 && (
          <div className="text-center py-8 text-gray-500 text-xs">
            No packets match the selected search/filter criteria.
          </div>
        )}
      </div>
    </div>
  );
}
