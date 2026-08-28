import { useState, useEffect } from "react";
import type { RemoteRoutePreference } from "../adapters/tauri/types";
import {
  X,
  Maximize2,
  Minimize2,
  Monitor,
  Keyboard,
  Mouse,
  Volume2,
  VolumeX,
  Clipboard,
  MoreHorizontal,
  Wifi,
  WifiOff,
  ChevronDown,
  Power,
  RefreshCw,
  Lock,
  Send,
} from "lucide-react";

export type { RemoteRoutePreference };

const ROUTE_OPTIONS: ReadonlyArray<{
  value: RemoteRoutePreference;
  label: string;
}> = [
  { value: "auto", label: "Auto" },
  { value: "lan", label: "LAN" },
  { value: "wan_relay", label: "WAN Relay" },
];

export interface RemoteSessionModalProps {
  device: {
    name: string;
    id: string;
    os: string;
  };
  onClose: () => void;
  /**
   * The service boundary receives the route enum only. Authentication and
   * relay details stay owned by mrd-service and are never modal props.
   */
  onRoutePreferenceChange?: (routePreference: RemoteRoutePreference) => void;
}

export function RemoteSessionModal({
  device,
  onClose,
  onRoutePreferenceChange,
}: RemoteSessionModalProps) {
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [muted, setMuted] = useState(false);
  const [latency, setLatency] = useState(24);
  const [quality, setQuality] = useState(85);
  const [elapsed, setElapsed] = useState(0);
  const [showControls, setShowControls] = useState(true);
  const [showToolbar, setShowToolbar] = useState(false);
  const [routePreference, setRoutePreference] =
    useState<RemoteRoutePreference>("auto");

  useEffect(() => {
    const timer = setInterval(() => {
      setElapsed((e) => e + 1);
      setLatency((l) => Math.max(12, Math.min(60, l + Math.floor(Math.random() * 7) - 3)));
      setQuality((q) => Math.max(70, Math.min(98, q + Math.floor(Math.random() * 5) - 2)));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const formatTime = (s: number) => {
    const m = Math.floor(s / 60);
    const sec = s % 60;
    return `${m.toString().padStart(2, "0")}:${sec.toString().padStart(2, "0")}`;
  };

  const handleRoutePreferenceChange = (
    nextRoutePreference: RemoteRoutePreference,
  ) => {
    setRoutePreference(nextRoutePreference);
    onRoutePreferenceChange?.(nextRoutePreference);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
      <div
        className={`flex flex-col bg-[#1a1a2e] border border-gray-700 shadow-2xl overflow-hidden transition-all duration-300 ${
          isFullscreen
            ? "w-full h-full rounded-none"
            : "w-[90vw] max-w-5xl h-[80vh] rounded-xl"
        }`}
      >
        {/* Title bar - keep dark for remote session window */}
        <div className="flex items-center gap-3 px-4 py-2.5 bg-[#232340] border-b border-white/10 shrink-0">
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded-full bg-red-500/80 hover:bg-red-500 cursor-pointer transition-colors" onClick={onClose} />
            <div className="w-3 h-3 rounded-full bg-yellow-500/80 hover:bg-yellow-500 cursor-pointer transition-colors" />
            <div
              className="w-3 h-3 rounded-full bg-green-500/80 hover:bg-green-500 cursor-pointer transition-colors"
              onClick={() => setIsFullscreen(!isFullscreen)}
            />
          </div>

          <div className="flex-1 flex items-center justify-center gap-2">
            <div className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
            <span className="text-gray-200 font-medium" style={{ fontSize: 13 }}>
              {device.name}
            </span>
            <span className="text-gray-400" style={{ fontSize: 12 }}>
              {device.id}
            </span>
          </div>

          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-white/10 text-gray-300" style={{ fontSize: 12 }}>
              <Wifi className="w-3 h-3 text-green-400" />
              <span>{latency}ms</span>
            </div>
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-white/10 text-gray-300" style={{ fontSize: 12 }}>
              <Monitor className="w-3 h-3 text-blue-400" />
              <span>{quality}%</span>
            </div>
            <div className="px-2.5 py-1 rounded-md bg-white/10 text-gray-300" style={{ fontSize: 12 }}>
              {formatTime(elapsed)}
            </div>
            <button
              onClick={() => setIsFullscreen(!isFullscreen)}
              className="p-1.5 rounded-md hover:bg-white/10 text-gray-300 hover:text-white transition-colors"
            >
              {isFullscreen ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-md hover:bg-red-500/20 text-gray-300 hover:text-red-400 transition-colors"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        <div className="flex items-center gap-3 px-4 py-2 bg-[#1f1f36] border-b border-white/10 shrink-0">
          <span className="text-gray-400" style={{ fontSize: 11 }}>
            Connection route
          </span>
          <div
            aria-label="Connection route"
            className="flex items-center gap-1"
            role="radiogroup"
          >
            {ROUTE_OPTIONS.map((option) => (
              <label
                className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md cursor-pointer transition-colors ${
                  routePreference === option.value
                    ? "bg-blue-500/20 text-blue-300"
                    : "text-gray-400 hover:bg-white/5 hover:text-gray-200"
                }`}
                key={option.value}
              >
                <input
                  checked={routePreference === option.value}
                  className="sr-only"
                  name="remote-session-route"
                  onChange={() => handleRoutePreferenceChange(option.value)}
                  type="radio"
                  value={option.value}
                />
                <span>{option.label}</span>
              </label>
            ))}
          </div>
        </div>

        {/* Toolbar */}
        <div className="flex items-center gap-1 px-4 py-2 bg-[#232340]/80 border-b border-white/10 shrink-0">
          <ToolbarBtn icon={<Mouse className="w-3.5 h-3.5" />} label="鼠标" />
          <ToolbarBtn icon={<Keyboard className="w-3.5 h-3.5" />} label="键盘" />
          <ToolbarBtn
            icon={muted ? <VolumeX className="w-3.5 h-3.5" /> : <Volume2 className="w-3.5 h-3.5" />}
            label={muted ? "静音" : "音频"}
            onClick={() => setMuted(!muted)}
            active={!muted}
          />
          <ToolbarBtn icon={<Clipboard className="w-3.5 h-3.5" />} label="剪贴板" />
          <div className="w-px h-4 bg-white/10 mx-1" />
          <ToolbarBtn icon={<Lock className="w-3.5 h-3.5" />} label="锁屏" />
          <ToolbarBtn icon={<RefreshCw className="w-3.5 h-3.5" />} label="刷新" />
          <ToolbarBtn icon={<Power className="w-3.5 h-3.5" />} label="重启" danger />
          <div className="flex-1" />
          <div className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-white/5 text-gray-300" style={{ fontSize: 11 }}>
            <span>画质</span>
            <div className="flex gap-0.5">
              {[1,2,3,4,5].map((i) => (
                <div key={i} className={`w-1 h-2.5 rounded-sm ${i <= Math.round(quality/20) ? "bg-blue-400" : "bg-white/15"}`} />
              ))}
            </div>
          </div>
        </div>

        {/* Remote native surface placeholder */}
        <div className="flex-1 relative bg-[#1a1a2e] overflow-hidden cursor-crosshair select-none">
          {/* Connection quality overlay */}
          <div className="absolute top-3 right-3 flex flex-col gap-2 items-end">
            <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-black/60 backdrop-blur-sm border border-white/10 text-gray-300" style={{ fontSize: 11 }}>
              <div className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
              <span>连接稳定</span>
            </div>
          </div>

          {/* OS badge */}
          <div className="absolute bottom-3 left-3 px-2.5 py-1.5 rounded-lg bg-black/60 backdrop-blur-sm border border-white/10 text-gray-400" style={{ fontSize: 11 }}>
            远程主机: {device.name} · {device.os}
          </div>
        </div>

        {/* Status bar */}
        <div className="flex items-center justify-between px-4 py-2 bg-[#232340] border-t border-white/10 shrink-0">
          <div className="flex items-center gap-4">
            <StatusItem label="分辨率" value="1920×1080" />
            <StatusItem label="帧率" value="60 fps" />
            <StatusItem label="带宽" value="4.2 MB/s" />
          </div>
          <div className="flex items-center gap-1 text-gray-400" style={{ fontSize: 11 }}>
            <Lock className="w-3 h-3 text-green-400" />
            <span className="text-green-400">TLS 1.3 加密</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function ToolbarBtn({
  icon,
  label,
  onClick,
  active,
  danger,
}: {
  icon: React.ReactNode;
  label: string;
  onClick?: () => void;
  active?: boolean;
  danger?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      title={label}
      className={`flex items-center gap-1.5 px-2 py-1.5 rounded-md transition-colors ${
        danger
          ? "text-red-400/70 hover:bg-red-500/10 hover:text-red-400"
          : active === false
          ? "text-gray-500 hover:bg-white/5 hover:text-gray-300"
          : "text-gray-300 hover:bg-white/8 hover:text-gray-100"
      }`}
    >
      {icon}
      <span style={{ fontSize: 11 }}>{label}</span>
    </button>
  );
}

function StatusItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center gap-1.5" style={{ fontSize: 11 }}>
      <span className="text-gray-500">{label}</span>
      <span className="text-gray-300">{value}</span>
    </div>
  );
}
