import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router";
import { devices } from "./deviceData";
import {
  X,
  Minus,
  Square,
  Monitor,
  Keyboard,
  Mouse,
  Volume2,
  VolumeX,
  Clipboard,
  Wifi,
  Power,
  RefreshCw,
  Lock,
  Maximize2,
  Minimize2,
  ArrowLeft,
  Signal,
} from "lucide-react";
import { useTheme } from "./ThemeContext";

export function RemoteSessionPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { isDark } = useTheme();
  const device = devices.find((d) => d.id === id);

  const [muted, setMuted] = useState(false);
  const [latency, setLatency] = useState(device?.ping ?? 24);
  const [quality, setQuality] = useState(87);
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setElapsed((e) => e + 1);
      setLatency((l) => Math.max(10, Math.min(60, l + Math.floor(Math.random() * 7) - 3)));
      setQuality((q) => Math.max(70, Math.min(98, q + Math.floor(Math.random() * 5) - 2)));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const formatTime = (s: number) => {
    const m = Math.floor(s / 60);
    const sec = s % 60;
    return `${m.toString().padStart(2, "0")}:${sec.toString().padStart(2, "0")}`;
  };

  const handleDisconnect = () => {
    if (device) navigate(`/devices/${device.id}`);
    else navigate("/");
  };

  if (!device) {
    return (
      <div className="flex items-center justify-center h-screen bg-[#1a1a1a]">
        <div className="text-center">
          <div className="text-gray-500 mb-2" style={{ fontSize: 48 }}>?</div>
          <div className="text-gray-400" style={{ fontSize: 16 }}>设备未找到</div>
          <button
            onClick={() => navigate("/")}
            className="mt-3 px-4 py-2 rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors"
            style={{ fontSize: 13 }}
          >
            返回首页
          </button>
        </div>
      </div>
    );
  }

  const Icon = device.icon;

  return (
    <div className="flex flex-col h-screen w-screen bg-[#1a1a2e] overflow-hidden">
      {/* Title bar — unified window style with all controls */}
      <div
        className="flex items-center h-11 bg-[#232340] border-b border-white/10 shrink-0 select-none"
        style={{ WebkitAppRegion: "drag" } as React.CSSProperties}
      >
        {/* Left: back + device info */}
        <div className="flex items-center gap-2 px-3 shrink-0" style={{ WebkitAppRegion: "no-drag" } as React.CSSProperties}>
          <button
            onClick={handleDisconnect}
            className="p-1 rounded-md text-gray-400 hover:text-gray-200 hover:bg-white/8 transition-colors"
            title="返回"
          >
            <ArrowLeft style={{ width: 14, height: 14 }} />
          </button>

          <div className="w-px h-4 bg-white/10" />

          <div className="flex items-center gap-2">
            <div className="relative w-6 h-6 rounded-md bg-blue-900/40 flex items-center justify-center">
              <Icon style={{ width: 13, height: 13 }} className="text-blue-400" />
              <div className="absolute -bottom-0.5 -right-0.5 w-2 h-2 rounded-full bg-green-500 border border-[#232340]" />
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-gray-200" style={{ fontSize: 13 }}>{device.name}</span>
              <span className="text-gray-500" style={{ fontSize: 11 }}>{device.os}</span>
            </div>
          </div>
        </div>

        {/* Center: session controls */}
        <div className="flex-1 flex items-center justify-center gap-1" style={{ WebkitAppRegion: "no-drag" } as React.CSSProperties}>
          <CtrlBtn icon={<Mouse style={{ width: 13, height: 13 }} />} label="鼠标" />
          <CtrlBtn icon={<Keyboard style={{ width: 13, height: 13 }} />} label="键盘" />
          <CtrlBtn
            icon={muted ? <VolumeX style={{ width: 13, height: 13 }} /> : <Volume2 style={{ width: 13, height: 13 }} />}
            label={muted ? "静音" : "音频"}
            onClick={() => setMuted(!muted)}
            active={!muted}
          />
          <CtrlBtn icon={<Clipboard style={{ width: 13, height: 13 }} />} label="剪贴板" />

          <div className="w-px h-4 bg-white/10 mx-0.5" />

          <CtrlBtn icon={<Lock style={{ width: 13, height: 13 }} />} label="锁屏" />
          <CtrlBtn icon={<RefreshCw style={{ width: 12, height: 12 }} />} label="刷新" />
          <CtrlBtn icon={<Power style={{ width: 13, height: 13 }} />} label="关机" danger />
        </div>

        {/* Right: status + window controls */}
        <div className="flex items-center gap-1.5 pr-1 shrink-0" style={{ WebkitAppRegion: "no-drag" } as React.CSSProperties}>
          {/* Status indicators */}
          <div className="flex items-center gap-1 px-2 py-0.5 rounded-md bg-white/6 mr-1">
            <Wifi style={{ width: 11, height: 11 }} className={latency < 30 ? "text-green-400" : latency < 50 ? "text-yellow-400" : "text-red-400"} />
            <span className="text-gray-300" style={{ fontSize: 11 }}>{latency}ms</span>
            <div className="w-px h-3 bg-white/10 mx-0.5" />
            <Signal style={{ width: 11, height: 11 }} className="text-blue-400" />
            <span className="text-gray-300" style={{ fontSize: 11 }}>{quality}%</span>
            <div className="w-px h-3 bg-white/10 mx-0.5" />
            <span className="text-gray-400" style={{ fontSize: 11 }}>{formatTime(elapsed)}</span>
          </div>

          {/* Disconnect */}
          <button
            onClick={handleDisconnect}
            className="flex items-center gap-1 px-2 py-1 rounded-md bg-red-500/15 text-red-400 hover:bg-red-500/25 transition-colors"
            style={{ fontSize: 11 }}
          >
            <Power style={{ width: 11, height: 11 }} />
            断开
          </button>

          {/* Window controls */}
          <div className="flex items-center h-full ml-1">
            <button className="flex items-center justify-center w-9 h-8 text-gray-500 hover:bg-white/8 hover:text-gray-300 transition-colors rounded-sm">
              <Minus style={{ width: 14, height: 14 }} />
            </button>
            <button className="flex items-center justify-center w-9 h-8 text-gray-500 hover:bg-white/8 hover:text-gray-300 transition-colors rounded-sm">
              <Square style={{ width: 11, height: 11 }} />
            </button>
            <button
              onClick={handleDisconnect}
              className="flex items-center justify-center w-9 h-8 text-gray-500 hover:bg-red-500 hover:text-white transition-colors rounded-sm"
            >
              <X style={{ width: 14, height: 14 }} />
            </button>
          </div>
        </div>
      </div>

      {/* Remote screen — full area */}
      <div className="flex-1 relative overflow-hidden cursor-crosshair select-none">
        <img
          src="https://images.unsplash.com/photo-1651832710372-a2b0da73a98f?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxyZW1vdGUlMjBkZXNrdG9wJTIwY29tcHV0ZXIlMjBzY3JlZW58ZW58MXx8fHwxNzcyNjE5MDE0fDA&ixlib=rb-4.1.0&q=80&w=1080"
          alt="Remote desktop"
          className="w-full h-full object-cover opacity-90"
          draggable={false}
        />

        {/* Connection quality overlay */}
        <div className="absolute top-3 right-3 flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-black/60 backdrop-blur-sm border border-white/10 text-gray-300" style={{ fontSize: 11 }}>
          <div className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
          连接稳定
        </div>

        {/* Device info badge */}
        <div className="absolute bottom-3 left-3 px-2.5 py-1.5 rounded-lg bg-black/60 backdrop-blur-sm border border-white/10 text-gray-400" style={{ fontSize: 11 }}>
          {device.name} · {device.os} · 1920×1080
        </div>
      </div>

      {/* Status bar */}
      <div className="flex items-center justify-between px-4 py-1.5 bg-[#232340] border-t border-white/10 shrink-0">
        <div className="flex items-center gap-4">
          <StatusItem label="分辨率" value="1920×1080" />
          <StatusItem label="帧率" value="60 fps" />
          <StatusItem label="带宽" value="4.2 MB/s" />
        </div>
        <div className="flex items-center gap-1 text-green-400" style={{ fontSize: 11 }}>
          <Lock style={{ width: 11, height: 11 }} />
          TLS 1.3 加密
        </div>
      </div>
    </div>
  );
}

function CtrlBtn({
  icon, label, onClick, active, danger,
}: {
  icon: React.ReactNode; label: string; onClick?: () => void; active?: boolean; danger?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      title={label}
      className={`flex items-center gap-1 px-1.5 py-1 rounded-md transition-colors ${
        danger
          ? "text-red-400/70 hover:bg-red-500/15 hover:text-red-400"
          : active === false
          ? "text-gray-500 hover:bg-white/6 hover:text-gray-300"
          : "text-gray-400 hover:bg-white/8 hover:text-gray-200"
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
