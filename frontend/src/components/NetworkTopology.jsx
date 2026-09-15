import React, { useState } from 'react';
import { Network, Server, ArrowRight } from 'lucide-react';

export default function NetworkTopology({ topology }) {
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedEdge, setSelectedEdge] = useState(null);

  const nodes = topology?.nodes || [];
  const edges = topology?.edges || [];

  if (nodes.length === 0) {
    return (
      <div className="glass-panel p-8 rounded-2xl border border-gray-800 text-center text-gray-500 text-xs">
        No network communication topology available for this capture.
      </div>
    );
  }

  // Calculate circular layout positions for nodes
  const width = 600;
  const height = 360;
  const centerX = width / 2;
  const centerY = height / 2;
  const radius = Math.min(width, height) / 2 - 60;

  const nodePositions = {};
  nodes.forEach((node, idx) => {
    const angle = (idx / nodes.length) * 2 * Math.PI - Math.PI / 2;
    nodePositions[node.id] = {
      x: centerX + radius * Math.cos(angle),
      y: centerY + radius * Math.sin(angle),
      label: node.label,
      count: node.packet_count
    };
  });

  return (
    <div className="glass-panel p-6 rounded-2xl border border-gray-800 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Network className="w-5 h-5 text-blue-400" />
          <h3 className="text-sm font-bold text-white">Network Communication Topology</h3>
        </div>
        <span className="text-xs text-gray-400">
          {nodes.length} Unique Hosts • {edges.length} Active Links
        </span>
      </div>

      <div className="relative border border-gray-800/80 rounded-xl bg-gray-950/60 p-4 flex flex-col lg:flex-row items-center justify-between gap-4">
        {/* Interactive SVG Network Graph */}
        <div className="w-full max-w-[600px] overflow-hidden">
          <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-auto max-h-[380px]">
            <defs>
              <marker
                id="arrowhead"
                markerWidth="8"
                markerHeight="6"
                refX="22"
                refY="3"
                orient="auto"
              >
                <polygon points="0 0, 8 3, 0 6" fill="#3b82f6" />
              </marker>
            </defs>

            {/* Edges */}
            {edges.map((edge, idx) => {
              const srcPos = nodePositions[edge.source];
              const dstPos = nodePositions[edge.target];
              if (!srcPos || !dstPos) return null;

              const isSelected = selectedEdge === edge;

              return (
                <g key={idx} onClick={() => { setSelectedEdge(edge); setSelectedNode(null); }} className="cursor-pointer">
                  <line
                    x1={srcPos.x}
                    y1={srcPos.y}
                    x2={dstPos.x}
                    y2={dstPos.y}
                    stroke={isSelected ? '#60a5fa' : '#334155'}
                    strokeWidth={isSelected ? 3 : Math.min(1 + Math.log2(edge.packets || 1), 5)}
                    strokeDasharray={edge.protocol?.includes('UDP') ? '4 4' : 'none'}
                    markerEnd="url(#arrowhead)"
                    className="hover:stroke-blue-400 transition-colors"
                  />
                </g>
              );
            })}

            {/* Nodes */}
            {nodes.map((node) => {
              const pos = nodePositions[node.id];
              if (!pos) return null;

              const isSelected = selectedNode?.id === node.id;

              return (
                <g
                  key={node.id}
                  transform={`translate(${pos.x}, ${pos.y})`}
                  onClick={() => { setSelectedNode(node); setSelectedEdge(null); }}
                  className="cursor-pointer group"
                >
                  <circle
                    r="18"
                    className={`transition-all ${
                      isSelected
                        ? 'fill-blue-600 stroke-white stroke-2'
                        : 'fill-gray-900 stroke-blue-500/60 hover:stroke-blue-400 stroke-2'
                    }`}
                  />
                  <text
                    textAnchor="middle"
                    dy="4"
                    fill="#ffffff"
                    fontSize="9"
                    fontWeight="bold"
                    fontFamily="monospace"
                  >
                    {node.id.split('.').pop()}
                  </text>

                  {/* Node Label Below */}
                  <text
                    textAnchor="middle"
                    dy="32"
                    fill="#94a3b8"
                    fontSize="9"
                    fontFamily="monospace"
                    className="group-hover:fill-white font-semibold"
                  >
                    {node.id}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Selected Node / Edge Details Panel */}
        <div className="w-full lg:w-64 p-4 rounded-xl bg-gray-900/80 border border-gray-800 text-xs space-y-3 shrink-0">
          {selectedNode ? (
            <div>
              <div className="flex items-center space-x-2 text-blue-400 font-bold mb-2">
                <Server className="w-4 h-4" />
                <span>Host Details</span>
              </div>
              <p className="text-gray-400">IP Address:</p>
              <p className="font-mono text-white font-bold text-sm">{selectedNode.id}</p>
              <div className="mt-3 pt-2 border-t border-gray-800 space-y-1">
                <p className="text-gray-400">Total Packets Handled:</p>
                <p className="font-mono text-emerald-400 font-bold">{selectedNode.packet_count}</p>
              </div>
            </div>
          ) : selectedEdge ? (
            <div>
              <div className="flex items-center space-x-2 text-blue-400 font-bold mb-2">
                <ArrowRight className="w-4 h-4" />
                <span>Communication Link</span>
              </div>
              <p className="text-gray-400">Source → Destination:</p>
              <p className="font-mono text-white font-semibold">{selectedEdge.source}</p>
              <p className="font-mono text-blue-400 font-semibold mb-2">↓ {selectedEdge.target}</p>

              <div className="pt-2 border-t border-gray-800 space-y-1">
                <p className="text-gray-400">Packets Transferred: <span className="font-mono text-white font-bold">{selectedEdge.packets}</span></p>
                <p className="text-gray-400">Bytes Transferred: <span className="font-mono text-white font-bold">{selectedEdge.bytes.toLocaleString()} bytes</span></p>
                <p className="text-gray-400">Protocols Used: <span className="font-mono text-amber-300 font-bold">{selectedEdge.protocol}</span></p>
              </div>
            </div>
          ) : (
            <div className="text-center text-gray-500 py-6">
              Click any node or link in the topology graph to inspect detailed traffic metrics.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
