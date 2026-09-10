import { useState, useEffect, useRef } from "react";
import { useParams, useNavigate } from "react-router";
import { devices, type Device } from "./deviceData";
import {
  ArrowLeft,
  Monitor,
  FolderOpen,
  AppWindow,
  Wifi,
  WifiOff,
  MapPin,
  Clock,
  Cpu,
  HardDrive,
  MemoryStick,
  Power,
  RefreshCw,
  Lock,
  Copy,
  Star,
  MoreVertical,
  Keyboard,
  Mouse,
  Volume2,
  VolumeX,
  Clipboard,
  Maximize2,
  Minimize2,
  X,
  Send,
  Pause,
  Play,
  Upload,
  Download,
  File,
  Folder,
  ChevronRight,
  Minus,
  Square,
  Globe,
  FileText,
  Image,
  Music,
  Terminal,
  Calculator,
  Mail,
  MessageSquare,
  Presentation,
  Database,
  Code,
  Settings,
  ExternalLink,
  Activity,
  ArrowUp,
  Home,
  Search,
  LayoutGrid,
  List,
  Plus,
  Laptop,
  Server,
  Smartphone,
  Trash2,
  Scissors,
  ClipboardPaste,
  Edit3,
  Info,
  ArrowRightLeft,
  ChevronUp,
} from "lucide-react";
import { useTheme } from "./ThemeContext";
import { useDetailBar } from "./DetailBarContext";

type TabType = "remote" | "files" | "apps";

const remoteApps = [
  {
    id: "vscode",
    name: "Visual Studio Code",
    icon: Code,
    color: "bg-blue-500",
    running: true,
    description: "代码编辑器",
    screenshot: "https://images.unsplash.com/photo-1753998943228-73470750c597?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxjb2RlJTIwZWRpdG9yJTIwSURFJTIwZGFyayUyMHRoZW1lfGVufDF8fHx8MTc3MjYyMTQ0OXww&ixlib=rb-4.1.0&q=80&w=1080",
  },
  {
    id: "excel",
    name: "Microsoft Excel",
    icon: FileText,
    color: "bg-green-600",
    running: true,
    description: "电子表格",
    screenshot: "https://images.unsplash.com/photo-1584472666879-7d92db132958?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxzcHJlYWRzaGVldCUyMGRhdGElMjB0YWJsZSUyMGFwcGxpY2F0aW9ufGVufDF8fHx8MTc3MjYyMTQ1MHww&ixlib=rb-4.1.0&q=80&w=1080",
  },
  {
    id: "browser",
    name: "Google Chrome",
    icon: Globe,
    color: "bg-yellow-500",
    running: true,
    description: "网页浏览器",
    screenshot: "https://images.unsplash.com/photo-1762330918012-5f2c1d31c521?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHx3ZWIlMjBicm93c2VyJTIwY2hyb21lJTIwaW50ZXJmYWNlfGVufDF8fHx8MTc3MjYyMTQ1MXww&ixlib=rb-4.1.0&q=80&w=1080",
  },
  {
    id: "terminal",
    name: "Windows Terminal",
    icon: Terminal,
    color: "bg-gray-800",
    running: false,
    description: "命令行终端",
    screenshot: null,
  },
  {
    id: "calculator",
    name: "计算器",
    icon: Calculator,
    color: "bg-indigo-500",
    running: false,
    description: "系统计算器",
    screenshot: null,
  },
  {
    id: "mail",
    name: "Outlook",
    icon: Mail,
    color: "bg-blue-700",
    running: false,
    description: "邮件客户端",
    screenshot: null,
  },
  {
    id: "chat",
    name: "微信",
    icon: MessageSquare,
    color: "bg-green-500",
    running: false,
    description: "即时通讯",
    screenshot: null,
  },
  {
    id: "ppt",
    name: "PowerPoint",
    icon: Presentation,
    color: "bg-orange-600",
    running: false,
    description: "演示文稿",
    screenshot: null,
  },
];

const remoteFiles = [
  { name: "Documents", type: "folder" as const, size: "—", modified: "2026-03-03" },
  { name: "Downloads", type: "folder" as const, size: "—", modified: "2026-03-04" },
  { name: "Desktop", type: "folder" as const, size: "—", modified: "2026-03-04" },
  { name: "report_2026.pdf", type: "file" as const, size: "2.3 MB", modified: "2026-03-01" },
  { name: "config.json", type: "file" as const, size: "12 KB", modified: "2026-02-28" },
  { name: "backup.tar.gz", type: "file" as const, size: "890 MB", modified: "2026-02-27" },
  { name: "screenshot.png", type: "file" as const, size: "4.1 MB", modified: "2026-03-04" },
];

const allRemoteFiles = [
  { name: "Documents", type: "folder" as const, size: "—", modified: "2026-03-03", fileKind: "文件夹" },
  { name: "Downloads", type: "folder" as const, size: "—", modified: "2026-03-04", fileKind: "文件夹" },
  { name: "Desktop", type: "folder" as const, size: "—", modified: "2026-03-04", fileKind: "文件夹" },
  { name: "Pictures", type: "folder" as const, size: "—", modified: "2026-03-02", fileKind: "文件夹" },
  { name: "Music", type: "folder" as const, size: "—", modified: "2026-02-15", fileKind: "文件夹" },
  { name: "Videos", type: "folder" as const, size: "—", modified: "2026-02-20", fileKind: "文件夹" },
  { name: "report_2026.pdf", type: "file" as const, size: "2.3 MB", modified: "2026-03-01", fileKind: "PDF 文档" },
  { name: "config.json", type: "file" as const, size: "12 KB", modified: "2026-02-28", fileKind: "JSON 文件" },
  { name: "backup.tar.gz", type: "file" as const, size: "890 MB", modified: "2026-02-27", fileKind: "压缩包" },
  { name: "screenshot.png", type: "file" as const, size: "4.1 MB", modified: "2026-03-04", fileKind: "PNG 图片" },
  { name: "notes.txt", type: "file" as const, size: "4 KB", modified: "2026-03-04", fileKind: "文本文件" },
  { name: "presentation.pptx", type: "file" as const, size: "18 MB", modified: "2026-03-03", fileKind: "演示文稿" },
  { name: "database.sql", type: "file" as const, size: "156 KB", modified: "2026-02-25", fileKind: "SQL 文件" },
  { name: "logo.jpg", type: "file" as const, size: "320 KB", modified: "2026-03-02", fileKind: "JPEG 图片" },
];

const localFiles = [
  { name: "Projects", type: "folder" as const, size: "—", modified: "2026-03-04" },
  { name: "Pictures", type: "folder" as const, size: "—", modified: "2026-03-03" },
  { name: "Music", type: "folder" as const, size: "—", modified: "2026-02-20" },
  { name: "presentation.pptx", type: "file" as const, size: "18 MB", modified: "2026-03-04" },
  { name: "notes.txt", type: "file" as const, size: "4 KB", modified: "2026-03-04" },
  { name: "dataset.csv", type: "file" as const, size: "56 MB", modified: "2026-03-02" },
];

export function DeviceDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const device = devices.find((d) => d.id === id);
  const [activeTab, setActiveTab] = useState<TabType>("remote");
  const { isDark } = useTheme();
  const detailBar = useDetailBar();

  if (!device) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <div className="text-gray-400 mb-2" style={{ fontSize: 48 }}>?</div>
          <div className="text-gray-600" style={{ fontSize: 16 }}>设备未找到</div>
          <button
            onClick={() => navigate("/devices")}
            className="mt-3 px-4 py-2 rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors"
            style={{ fontSize: 13 }}
          >
            返回设备列表
          </button>
        </div>
      </div>
    );
  }

  const Icon = device.icon;
  const isOnline = device.status === "online";
  const tabs: { key: TabType; label: string; icon: typeof Monitor }[] = [
    { key: "remote", label: "远程桌面", icon: Monitor },
    { key: "files", label: "文件传输", icon: FolderOpen },
    { key: "apps", label: "远程应用", icon: AppWindow },
  ];

  const handleCollapse = () => {
    detailBar.collapse({
      deviceName: device.name,
      deviceIcon: Icon,
      isOnline,
      ping: device.ping,
      tabs,
      activeTab,
      setActiveTab: (key: string) => setActiveTab(key as TabType),
      onNavigateBack: () => navigate("/devices"),
    });
  };

  // Keep context payload in sync with local activeTab
  useEffect(() => {
    if (detailBar.collapsed && detailBar.payload) {
      detailBar.collapse({
        ...detailBar.payload,
        activeTab,
        setActiveTab: (key: string) => setActiveTab(key as TabType),
      });
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab]);

  // Clean up context when leaving this page
  useEffect(() => {
    return () => {
      detailBar.reset();
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="flex flex-col h-full">
      {/* Top bar: device info + tabs — slides up when collapsed into TitleBar */}
      <div
        className={`shrink-0 border-b transition-all duration-300 ease-in-out overflow-hidden ${
          isDark ? "bg-[#1e1e1e] border-gray-700" : "bg-white border-gray-200/70"
        }`}
        style={{ height: detailBar.collapsed ? 0 : 60, opacity: detailBar.collapsed ? 0 : 1 }}
      >
        <div className="flex items-center gap-4 px-6" style={{ height: 60 }}>
          <button
            onClick={() => navigate("/devices")}
            className={`p-1.5 rounded-md transition-colors ${isDark ? "text-gray-400 hover:text-gray-200 hover:bg-gray-800" : "text-gray-400 hover:text-gray-700 hover:bg-gray-100"}`}
          >
            <ArrowLeft style={{ width: 16, height: 16 }} />
          </button>

          <div className={`relative w-9 h-9 rounded-lg flex items-center justify-center ${isOnline ? (isDark ? "bg-blue-900/30" : "bg-blue-50") : (isDark ? "bg-gray-800" : "bg-gray-100")}`}>
            <Icon style={{ width: 18, height: 18 }} className={isOnline ? "text-blue-600" : "text-gray-400"} />
            <div className={`absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full border-2 ${isDark ? "border-[#1e1e1e]" : "border-white"} ${isOnline ? "bg-green-500" : "bg-gray-300"}`} />
          </div>

          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className={`font-medium truncate ${isDark ? "text-gray-100" : "text-gray-900"}`} style={{ fontSize: 15 }}>{device.name}</span>
              {device.favorite && <Star className="w-3.5 h-3.5 text-yellow-500 fill-yellow-500 shrink-0" />}
              <span className={`px-1.5 py-0.5 rounded text-white shrink-0 ${isOnline ? "bg-green-500" : "bg-gray-400"}`} style={{ fontSize: 10 }}>
                {isOnline ? "在线" : "离线"}
              </span>
            </div>
            <div className="flex items-center gap-3 mt-0.5">
              <span className={`font-mono ${isDark ? "text-gray-500" : "text-gray-400"}`} style={{ fontSize: 11 }}>{device.deviceId}</span>
              <span className={isDark ? "text-gray-600" : "text-gray-300"} style={{ fontSize: 11 }}>·</span>
              <span className={isDark ? "text-gray-500" : "text-gray-400"} style={{ fontSize: 11 }}>{device.os}</span>
              <span className={isDark ? "text-gray-600" : "text-gray-300"} style={{ fontSize: 11 }}>·</span>
              <span className={isDark ? "text-gray-500" : "text-gray-400"} style={{ fontSize: 11 }}>{device.ip}</span>
              {device.ping !== null && (
                <>
                  <span className={isDark ? "text-gray-600" : "text-gray-300"} style={{ fontSize: 11 }}>·</span>
                  <span className={`${device.ping < 30 ? "text-green-600" : "text-yellow-600"}`} style={{ fontSize: 11 }}>
                    {device.ping}ms
                  </span>
                </>
              )}
            </div>
          </div>

          {/* Tab buttons */}
          <div className="flex items-center gap-1 shrink-0">
            {tabs.map((tab) => {
              const TabIcon = tab.icon;
              const isActive = activeTab === tab.key;
              return (
                <button
                  key={tab.key}
                  onClick={() => setActiveTab(tab.key)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md transition-colors ${
                    isActive
                      ? isDark
                        ? "bg-blue-900/30 text-blue-400"
                        : "bg-blue-50 text-blue-600"
                      : isDark
                        ? "text-gray-400 hover:bg-gray-800 hover:text-gray-200"
                        : "text-gray-500 hover:bg-gray-100 hover:text-gray-700"
                  }`}
                  style={{ fontSize: 12 }}
                >
                  <TabIcon style={{ width: 14, height: 14 }} />
                  {tab.label}
                </button>
              );
            })}
          </div>

          <button className={`p-1.5 rounded-md transition-colors ${isDark ? "text-gray-400 hover:text-gray-200 hover:bg-gray-800" : "text-gray-400 hover:text-gray-700 hover:bg-gray-100"}`}>
            <MoreVertical style={{ width: 16, height: 16 }} />
          </button>

          {/* Collapse button */}
          <button
            onClick={handleCollapse}
            className={`p-1 rounded-md transition-colors ${isDark ? "text-gray-500 hover:text-gray-300 hover:bg-gray-800" : "text-gray-400 hover:text-gray-600 hover:bg-gray-100"}`}
            title="收起到标题栏"
          >
            <ChevronUp style={{ width: 14, height: 14 }} />
          </button>
        </div>
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-hidden">
        {activeTab === "remote" && <RemoteTab device={device} />}
        {activeTab === "files" && <FilesTab device={device} />}
        {activeTab === "apps" && <AppsTab device={device} />}
      </div>

      {/* Performance monitoring footer */}
      {isOnline && device.cpu !== null && (
        <PerformanceFooter device={device} />
      )}
    </div>
  );
}

/* ======================== Remote Desktop Tab ======================== */
function RemoteTab({ device }: { device: Device }) {
  const { isDark } = useTheme();
  const navigate = useNavigate();
  const [muted, setMuted] = useState(false);
  const [latency, setLatency] = useState(device.ping ?? 24);
  const [quality, setQuality] = useState(87);
  const [elapsed, setElapsed] = useState(0);
  const [connected, setConnected] = useState(false);
  const isOnline = device.status === "online";

  useEffect(() => {
    if (!connected) return;
    const timer = setInterval(() => {
      setElapsed((e) => e + 1);
      setLatency((l) => Math.max(10, Math.min(60, l + Math.floor(Math.random() * 7) - 3)));
      setQuality((q) => Math.max(70, Math.min(98, q + Math.floor(Math.random() * 5) - 2)));
    }, 1000);
    return () => clearInterval(timer);
  }, [connected]);

  const formatTime = (s: number) => {
    const m = Math.floor(s / 60);
    const sec = s % 60;
    return `${m.toString().padStart(2, "0")}:${sec.toString().padStart(2, "0")}`;
  };

  if (!isOnline) {
    return (
      <div className={`flex items-center justify-center h-full ${isDark ? "bg-[#1a1a1a]" : "bg-[#f0f2f5]"}`}>
        <div className="text-center">
          <WifiOff className={`w-12 h-12 mx-auto mb-3 ${isDark ? "text-gray-600" : "text-gray-300"}`} />
          <div className={isDark ? "text-gray-400" : "text-gray-500"} style={{ fontSize: 16 }}>设备当前离线</div>
          <div className={`mt-1 ${isDark ? "text-gray-500" : "text-gray-400"}`} style={{ fontSize: 13 }}>最后在线: {device.lastSeen}</div>
        </div>
      </div>
    );
  }

  if (!connected) {
    return (
      <div className={`flex items-center justify-center h-full ${isDark ? "bg-[#1a1a1a]" : "bg-[#f0f2f5]"}`}>
        <div className="text-center">
          <div className={`w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-4 ${isDark ? "bg-blue-900/30" : "bg-blue-50"}`}>
            <Monitor className="w-8 h-8 text-blue-600" />
          </div>
          <div className={`mb-1 ${isDark ? "text-gray-200" : "text-gray-800"}`} style={{ fontSize: 18 }}>连接到 {device.name}</div>
          <div className={`mb-6 ${isDark ? "text-gray-500" : "text-gray-400"}`} style={{ fontSize: 13 }}>{device.os} · {device.ip} · 延迟 {device.ping}ms</div>
          <button
            onClick={() => navigate(`/session/${device.id}`)}
            className="px-8 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors shadow-sm"
            style={{ fontSize: 14 }}
          >
            发起远程连接
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full bg-[#1a1a2e]">
      {/* Toolbar */}
      <div className="flex items-center gap-1 px-3 py-1.5 bg-[#232340] border-b border-white/10 shrink-0">
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

        <div className="flex items-center gap-3 mr-2">
          <div className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-white/8 text-gray-300" style={{ fontSize: 11 }}>
            <Wifi className="w-3 h-3 text-green-400" />
            <span>{latency}ms</span>
          </div>
          <div className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-white/8 text-gray-300" style={{ fontSize: 11 }}>
            <Monitor className="w-3 h-3 text-blue-400" />
            <span>{quality}%</span>
          </div>
          <div className="px-2 py-1 rounded-md bg-white/8 text-gray-300" style={{ fontSize: 11 }}>
            {formatTime(elapsed)}
          </div>
        </div>

        <button
          onClick={() => setConnected(false)}
          className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors"
          style={{ fontSize: 11 }}
        >
          <Power className="w-3 h-3" />
          断开
        </button>
      </div>

      {/* Screen */}
      <div className="flex-1 relative overflow-hidden cursor-crosshair select-none">
        <img
          src="https://images.unsplash.com/photo-1610529027273-97aa4ba7188c?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHx3aW5kb3dzJTIwZGVza3RvcCUyMHdhbGxwYXBlciUyMGxhbmRzY2FwZXxlbnwxfHx8fDE3NzI2MjE0NTB8MA&ixlib=rb-4.1.0&q=80&w=1080"
          alt="Remote desktop"
          className="w-full h-full object-cover opacity-90"
          draggable={false}
        />
        <div className="absolute top-3 right-3 flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-black/60 backdrop-blur-sm border border-white/10 text-gray-300" style={{ fontSize: 11 }}>
          <div className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
          连接稳定
        </div>
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
          <Lock className="w-3 h-3" />
          TLS 1.3 加密
        </div>
      </div>
    </div>
  );
}

/* ======================== File Transfer Tab ======================== */
type FileItem = { name: string; type: "folder" | "file"; size: string; modified: string; fileKind: string };

const deviceFileSystems: Record<string, FileItem[]> = {};
for (const d of devices) {
  if (d.id === "1") deviceFileSystems[d.id] = allRemoteFiles;
  else {
    deviceFileSystems[d.id] = [
      { name: "Documents", type: "folder", size: "—", modified: "2026-03-02", fileKind: "文件夹" },
      { name: "Photos", type: "folder", size: "—", modified: "2026-03-01", fileKind: "文件夹" },
      { name: "Downloads", type: "folder", size: "—", modified: "2026-03-03", fileKind: "文件夹" },
      { name: "workspace.code", type: "file", size: "1.2 KB", modified: "2026-03-03", fileKind: "Code 文件" },
      { name: "readme.md", type: "file", size: "8 KB", modified: "2026-02-28", fileKind: "Markdown" },
      { name: "deploy.sh", type: "file", size: "2 KB", modified: "2026-03-01", fileKind: "Shell 脚本" },
    ];
  }
}

function FilePane({
  deviceId, side, otherDeviceName, isDark, onSendToOther, dragOver,
}: {
  deviceId: string; side: "left" | "right"; otherDeviceName: string | null; isDark: boolean;
  onSendToOther: (fileNames: string[]) => void; dragOver: boolean;
}) {
  const dev = devices.find(d => d.id === deviceId);
  const devName = dev?.name ?? "未知设备";
  const contextMenuRef = useRef<HTMLDivElement>(null);
  const [currentPath, setCurrentPath] = useState<string[]>([devName, "Users", "Admin"]);
  const [selectedFiles, setSelectedFiles] = useState<Set<string>>(new Set());
  const [viewMode, setViewMode] = useState<"list" | "grid">("list");
  const [searchQuery, setSearchQuery] = useState("");
  const [contextMenuState, setContextMenuState] = useState<{ x: number; y: number; fileName: string; fileType: string } | null>(null);

  const files = (deviceFileSystems[deviceId] ?? allRemoteFiles).filter(f =>
    searchQuery ? f.name.toLowerCase().includes(searchQuery.toLowerCase()) : true
  );

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (contextMenuRef.current && !contextMenuRef.current.contains(e.target as Node)) setContextMenuState(null);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const handleContextMenu = (e: React.MouseEvent, fileName: string, fileType: string) => { e.preventDefault(); setContextMenuState({ x: e.clientX, y: e.clientY, fileName, fileType }); };
  const handleFileClick = (e: React.MouseEvent, fileName: string) => {
    if (e.ctrlKey || e.metaKey) {
      setSelectedFiles(prev => { const n = new Set(prev); if (n.has(fileName)) n.delete(fileName); else n.add(fileName); return n; });
    } else setSelectedFiles(new Set([fileName]));
  };
  const handleDoubleClick = (f: FileItem) => { if (f.type === "folder") { setCurrentPath(p => [...p, f.name]); setSelectedFiles(new Set()); } };
  const navigateUp = () => { if (currentPath.length > 1) { setCurrentPath(p => p.slice(0, -1)); setSelectedFiles(new Set()); } };
  const navigateHome = () => { setCurrentPath([devName, "Users", "Admin"]); setSelectedFiles(new Set()); };
  const navigateTo = (i: number) => { setCurrentPath(p => p.slice(0, i + 1)); setSelectedFiles(new Set()); };

  const handleDragStart = (e: React.DragEvent, fileName: string) => {
    const dragFiles = selectedFiles.has(fileName) ? Array.from(selectedFiles) : [fileName];
    e.dataTransfer.setData("fileTransfer", JSON.stringify({ files: dragFiles, fromSide: side, fromDeviceId: deviceId }));
    e.dataTransfer.effectAllowed = "copy";
  };

  const handlePaneDrop = (e: React.DragEvent) => {
    e.preventDefault();
    try {
      const parsed = JSON.parse(e.dataTransfer.getData("fileTransfer"));
      if (parsed.fromSide !== side) console.log(`Transfer ${parsed.files.join(", ")} → ${devName}`);
    } catch {}
  };

  const DevIcon = dev?.icon ?? Monitor;
  const getFileIcon = (f: FileItem) => {
    if (f.type === "folder") return <Folder className="w-4 h-4 text-yellow-500 shrink-0" />;
    if (f.name.endsWith(".png") || f.name.endsWith(".jpg")) return <Image className="w-4 h-4 text-green-500 shrink-0" />;
    if (f.name.endsWith(".pdf")) return <FileText className="w-4 h-4 text-red-500 shrink-0" />;
    if (f.name.endsWith(".mp3") || f.name.endsWith(".wav")) return <Music className="w-4 h-4 text-purple-500 shrink-0" />;
    return <File className={`w-4 h-4 shrink-0 ${isDark ? "text-gray-500" : "text-gray-400"}`} />;
  };

  return (
    <div className={`flex-1 flex flex-col min-w-0 relative ${dragOver ? (isDark ? "ring-2 ring-inset ring-blue-500/50" : "ring-2 ring-inset ring-blue-400/50") : ""}`}
      onDragOver={(e) => { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; }} onDrop={handlePaneDrop}>
      {dragOver && (
        <div className="absolute inset-0 z-10 flex items-center justify-center pointer-events-none bg-blue-500/5">
          <div className={`px-4 py-2 rounded-lg border-2 border-dashed ${isDark ? "border-blue-500/40 bg-[#1e1e1e]/90 text-blue-400" : "border-blue-400/40 bg-white/90 text-blue-600"}`} style={{ fontSize: 13 }}>
            <Download style={{ width: 16, height: 16, display: "inline", marginRight: 6, verticalAlign: -3 }} />拖放到此处传输
          </div>
        </div>
      )}
      {/* Toolbar */}
      <div className={`flex items-center gap-1.5 px-2 py-1 border-b shrink-0 ${isDark ? "bg-[#232323] border-gray-700" : "bg-white border-gray-200"}`}>
        <div className={`flex items-center gap-1.5 px-2 py-0.5 rounded-md mr-1 ${isDark ? "bg-[#2a2a2a]" : "bg-gray-50"}`}>
          <DevIcon style={{ width: 12, height: 12 }} className={isDark ? "text-gray-400" : "text-gray-500"} />
          <span className={isDark ? "text-gray-300" : "text-gray-600"} style={{ fontSize: 11 }}>{devName}</span>
          <div className={`w-1.5 h-1.5 rounded-full ${dev?.status === "online" ? "bg-green-500" : "bg-gray-400"}`} />
        </div>
        <div className={`w-px h-4 ${isDark ? "bg-gray-700" : "bg-gray-200"}`} />
        <button onClick={navigateUp} className={`p-1 rounded-md transition-colors ${isDark ? "text-gray-400 hover:bg-gray-700 hover:text-gray-200" : "text-gray-500 hover:bg-gray-100 hover:text-gray-700"} ${currentPath.length <= 1 ? "opacity-40 pointer-events-none" : ""}`} title="上级目录">
          <ArrowUp style={{ width: 13, height: 13 }} />
        </button>
        <button onClick={navigateHome} className={`p-1 rounded-md transition-colors ${isDark ? "text-gray-400 hover:bg-gray-700 hover:text-gray-200" : "text-gray-500 hover:bg-gray-100 hover:text-gray-700"}`} title="主目录">
          <Home style={{ width: 13, height: 13 }} />
        </button>
        <button className={`p-1 rounded-md transition-colors ${isDark ? "text-gray-400 hover:bg-gray-700 hover:text-gray-200" : "text-gray-500 hover:bg-gray-100 hover:text-gray-700"}`} title="刷新">
          <RefreshCw style={{ width: 12, height: 12 }} />
        </button>
        <div className={`flex-1 flex items-center gap-0.5 px-2 py-0.5 rounded-md min-w-0 ${isDark ? "bg-[#2a2a2a] border border-gray-700" : "bg-gray-50 border border-gray-200"}`}>
          {currentPath.map((seg, i) => (
            <span key={i} className="flex items-center gap-0.5 shrink-0">
              {i > 0 && <ChevronRight style={{ width: 9, height: 9 }} className={isDark ? "text-gray-600" : "text-gray-300"} />}
              <button onClick={() => navigateTo(i)} className={`px-0.5 rounded transition-colors truncate ${isDark ? "text-gray-300 hover:text-blue-400 hover:bg-gray-700" : "text-gray-600 hover:text-blue-600 hover:bg-gray-100"}`} style={{ fontSize: 10, maxWidth: 90 }}>{seg}</button>
            </span>
          ))}
        </div>
        <div className={`flex items-center gap-1 px-2 py-0.5 rounded-md w-32 ${isDark ? "bg-[#2a2a2a] border border-gray-700" : "bg-gray-50 border border-gray-200"}`}>
          <Search style={{ width: 11, height: 11 }} className={isDark ? "text-gray-500" : "text-gray-400"} />
          <input value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} placeholder="搜索..." className={`bg-transparent outline-none flex-1 min-w-0 placeholder-gray-500 ${isDark ? "text-gray-200" : "text-gray-700"}`} style={{ fontSize: 10 }} />
        </div>
        <div className={`flex items-center rounded-md overflow-hidden border ${isDark ? "border-gray-700" : "border-gray-200"}`}>
          <button onClick={() => setViewMode("list")} className={`p-1 transition-colors ${viewMode === "list" ? (isDark ? "bg-gray-700 text-gray-200" : "bg-gray-100 text-gray-700") : (isDark ? "text-gray-500 hover:text-gray-300" : "text-gray-400 hover:text-gray-600")}`}>
            <List style={{ width: 12, height: 12 }} />
          </button>
          <button onClick={() => setViewMode("grid")} className={`p-1 transition-colors ${viewMode === "grid" ? (isDark ? "bg-gray-700 text-gray-200" : "bg-gray-100 text-gray-700") : (isDark ? "text-gray-500 hover:text-gray-300" : "text-gray-400 hover:text-gray-600")}`}>
            <LayoutGrid style={{ width: 12, height: 12 }} />
          </button>
        </div>
      </div>
      {viewMode === "list" && (
        <div className={`flex items-center px-3 py-0.5 border-b shrink-0 ${isDark ? "border-gray-700/60 bg-[#232323]" : "border-gray-100 bg-white"}`}>
          <span className={`flex-1 ${isDark ? "text-gray-500" : "text-gray-400"}`} style={{ fontSize: 10 }}>名称</span>
          <span className={`w-24 text-right ${isDark ? "text-gray-500" : "text-gray-400"}`} style={{ fontSize: 10 }}>修改日期</span>
          <span className={`w-20 text-right ${isDark ? "text-gray-500" : "text-gray-400"}`} style={{ fontSize: 10 }}>类型</span>
          <span className={`w-16 text-right ${isDark ? "text-gray-500" : "text-gray-400"}`} style={{ fontSize: 10 }}>大小</span>
        </div>
      )}
      <div
        className={`flex-1 overflow-y-auto ${viewMode === "grid" ? "p-2" : ""} ${isDark ? "bg-[#1e1e1e]" : "bg-white"}`}
        onClick={(e) => { if (e.target === e.currentTarget) setSelectedFiles(new Set()); }}
        onContextMenu={(e) => { if (e.target === e.currentTarget) { e.preventDefault(); setContextMenuState({ x: e.clientX, y: e.clientY, fileName: "", fileType: "background" }); } }}
      >
        {viewMode === "list" ? (
          <div>
            {files.map((f) => {
              const isSel = selectedFiles.has(f.name);
              return (
                <div key={f.name} draggable onDragStart={(e) => handleDragStart(e, f.name)}
                  onClick={(e) => handleFileClick(e, f.name)} onDoubleClick={() => handleDoubleClick(f)}
                  onContextMenu={(e) => handleContextMenu(e, f.name, f.type)}
                  className={`flex items-center px-3 py-1 cursor-default transition-colors ${isSel ? (isDark ? "bg-blue-900/30" : "bg-blue-50") : (isDark ? "hover:bg-[#252525]" : "hover:bg-gray-50/80")}`}>
                  <div className="flex items-center gap-2 flex-1 min-w-0">
                    {getFileIcon(f)}
                    <span className={`truncate ${isSel ? (isDark ? "text-blue-300" : "text-blue-700") : (isDark ? "text-gray-300" : "text-gray-700")}`} style={{ fontSize: 11 }}>{f.name}</span>
                  </div>
                  <span className={`w-24 text-right shrink-0 ${isDark ? "text-gray-500" : "text-gray-400"}`} style={{ fontSize: 10 }}>{f.modified}</span>
                  <span className={`w-20 text-right shrink-0 ${isDark ? "text-gray-500" : "text-gray-400"}`} style={{ fontSize: 10 }}>{f.fileKind}</span>
                  <span className={`w-16 text-right shrink-0 ${isDark ? "text-gray-500" : "text-gray-400"}`} style={{ fontSize: 10 }}>{f.size}</span>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="grid grid-cols-4 gap-1.5">
            {files.map((f) => {
              const isSel = selectedFiles.has(f.name);
              return (
                <div key={f.name} draggable onDragStart={(e) => handleDragStart(e, f.name)}
                  onClick={(e) => handleFileClick(e, f.name)} onDoubleClick={() => handleDoubleClick(f)}
                  onContextMenu={(e) => handleContextMenu(e, f.name, f.type)}
                  className={`flex flex-col items-center gap-1 p-2.5 rounded-lg cursor-default transition-colors ${isSel ? (isDark ? "bg-blue-900/30" : "bg-blue-50") : (isDark ? "hover:bg-[#252525]" : "hover:bg-gray-50")}`}>
                  {f.type === "folder" ? <Folder className="w-7 h-7 text-yellow-500" />
                    : f.name.endsWith(".png") || f.name.endsWith(".jpg") ? <Image className="w-7 h-7 text-green-500" />
                    : f.name.endsWith(".pdf") ? <FileText className="w-7 h-7 text-red-500" />
                    : <File className={`w-7 h-7 ${isDark ? "text-gray-500" : "text-gray-400"}`} />}
                  <span className={`text-center truncate w-full ${isSel ? (isDark ? "text-blue-300" : "text-blue-700") : (isDark ? "text-gray-300" : "text-gray-700")}`} style={{ fontSize: 10 }}>{f.name}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>
      <div className={`flex items-center justify-between px-3 py-0.5 border-t shrink-0 ${isDark ? "bg-[#232323] border-gray-700" : "bg-white border-gray-200"}`}>
        <div className="flex items-center gap-2">
          <span className={isDark ? "text-gray-500" : "text-gray-400"} style={{ fontSize: 9 }}>{files.length} 个项目</span>
          {selectedFiles.size > 0 && <span className={isDark ? "text-gray-400" : "text-gray-500"} style={{ fontSize: 9 }}>已选择 {selectedFiles.size} 项</span>}
        </div>
        <div className="flex items-center gap-1">
          <Lock style={{ width: 8, height: 8 }} className="text-green-500" />
          <span className="text-green-600" style={{ fontSize: 9 }}>E2E</span>
        </div>
      </div>
      {contextMenuState && (
        <div ref={contextMenuRef} className={`fixed z-50 rounded-lg border shadow-lg py-1 min-w-[180px] ${isDark ? "bg-[#2a2a2a] border-gray-700" : "bg-white border-gray-200"}`} style={{ left: contextMenuState.x, top: contextMenuState.y }}>
          {contextMenuState.fileType !== "background" ? (
            <>
              {contextMenuState.fileType === "folder" && (
                <CtxItem icon={<FolderOpen style={{ width: 13, height: 13 }} />} label="打开" onClick={() => { handleDoubleClick({ name: contextMenuState.fileName, type: "folder", size: "", modified: "", fileKind: "" }); setContextMenuState(null); }} isDark={isDark} />
              )}
              <CtxItem icon={<Download style={{ width: 13, height: 13 }} />} label="下载到本地" onClick={() => setContextMenuState(null)} isDark={isDark} />
              {otherDeviceName && (
                <CtxItem icon={<Send style={{ width: 13, height: 13 }} />} label={`发送到 ${otherDeviceName}`}
                  onClick={() => { onSendToOther([contextMenuState.fileName]); setContextMenuState(null); }} isDark={isDark} />
              )}
              <div className={`h-px mx-2 my-1 ${isDark ? "bg-gray-700" : "bg-gray-200"}`} />
              <CtxItem icon={<Scissors style={{ width: 13, height: 13 }} />} label="剪切" onClick={() => setContextMenuState(null)} isDark={isDark} />
              <CtxItem icon={<Copy style={{ width: 13, height: 13 }} />} label="复制" onClick={() => setContextMenuState(null)} isDark={isDark} />
              <CtxItem icon={<Edit3 style={{ width: 13, height: 13 }} />} label="重命名" onClick={() => setContextMenuState(null)} isDark={isDark} />
              <CtxItem icon={<Trash2 style={{ width: 13, height: 13 }} />} label="删除" onClick={() => setContextMenuState(null)} isDark={isDark} danger />
              <div className={`h-px mx-2 my-1 ${isDark ? "bg-gray-700" : "bg-gray-200"}`} />
              <CtxItem icon={<Info style={{ width: 13, height: 13 }} />} label="属性" onClick={() => setContextMenuState(null)} isDark={isDark} />
            </>
          ) : (
            <>
              <CtxItem icon={<Upload style={{ width: 13, height: 13 }} />} label="上传文件到此处" onClick={() => setContextMenuState(null)} isDark={isDark} />
              <CtxItem icon={<Folder style={{ width: 13, height: 13 }} />} label="新建文件夹" onClick={() => setContextMenuState(null)} isDark={isDark} />
              <div className={`h-px mx-2 my-1 ${isDark ? "bg-gray-700" : "bg-gray-200"}`} />
              <CtxItem icon={<ClipboardPaste style={{ width: 13, height: 13 }} />} label="粘贴" onClick={() => setContextMenuState(null)} isDark={isDark} />
              <CtxItem icon={<RefreshCw style={{ width: 13, height: 13 }} />} label="刷新" onClick={() => setContextMenuState(null)} isDark={isDark} />
            </>
          )}
        </div>
      )}
    </div>
  );
}

function FilesTab({ device }: { device: Device }) {
  const { isDark } = useTheme();
  const isOnline = device.status === "online";

  const [leftDeviceId, setLeftDeviceId] = useState(device.id);
  const [rightDeviceId, setRightDeviceId] = useState<string | null>(null);
  const [showAddMenu, setShowAddMenu] = useState(false);
  const [addMenuSide, setAddMenuSide] = useState<"left" | "right">("right");
  const addMenuRef = useRef<HTMLDivElement>(null);
  const addBtnRef = useRef<HTMLButtonElement>(null);
  const [dragOverSide, setDragOverSide] = useState<"left" | "right" | null>(null);

  const onlineDevices = devices.filter(d => d.status === "online");
  const leftDevice = devices.find(d => d.id === leftDeviceId);
  const rightDevice = rightDeviceId ? devices.find(d => d.id === rightDeviceId) : null;

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (addMenuRef.current && !addMenuRef.current.contains(e.target as Node) && addBtnRef.current && !addBtnRef.current.contains(e.target as Node)) setShowAddMenu(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const handleAddDevice = (dId: string) => {
    if (addMenuSide === "right") setRightDeviceId(dId);
    else setLeftDeviceId(dId);
    setShowAddMenu(false);
  };

  if (!isOnline) {
    return (
      <div className={`flex items-center justify-center h-full ${isDark ? "bg-[#1a1a1a]" : "bg-[#f0f2f5]"}`}>
        <div className="text-center">
          <WifiOff className={`w-12 h-12 mx-auto mb-3 ${isDark ? "text-gray-600" : "text-gray-300"}`} />
          <div className={isDark ? "text-gray-400" : "text-gray-500"} style={{ fontSize: 16 }}>设备离线，无法传输文件</div>
        </div>
      </div>
    );
  }

  return (
    <div className={`flex h-full overflow-hidden ${isDark ? "bg-[#1a1a1a]" : "bg-[#f0f2f5]"}`}>
      {/* Left pane */}
      <div
        className="flex-1 flex flex-col min-w-0"
        onDragOver={(e) => { e.preventDefault(); setDragOverSide("left"); }}
        onDragLeave={() => setDragOverSide(null)}
        onDrop={() => setDragOverSide(null)}
      >
        <FilePane
          deviceId={leftDeviceId}
          side="left"
          otherDeviceName={rightDevice?.name ?? null}
          isDark={isDark}
          onSendToOther={(fileNames) => console.log(`Send ${fileNames.join(", ")} to right pane`)}
          dragOver={dragOverSide === "left"}
        />
      </div>

      {/* Center divider with + button */}
      <div className={`relative w-8 shrink-0 flex flex-col items-center justify-center border-x ${isDark ? "bg-[#1a1a1a] border-gray-700/60" : "bg-[#f0f2f5] border-gray-200"}`}>
        <div className={`flex flex-col items-center gap-1 mb-2 ${isDark ? "text-gray-600" : "text-gray-300"}`}>
          <ChevronRight style={{ width: 12, height: 12 }} />
          <ChevronRight style={{ width: 12, height: 12, transform: "rotate(180deg)" }} />
        </div>

        <button
          ref={addBtnRef}
          onClick={() => { setAddMenuSide("right"); setShowAddMenu(!showAddMenu); }}
          className={`w-7 h-7 rounded-full flex items-center justify-center border transition-all ${isDark ? "bg-[#232323] border-gray-600 text-gray-400 hover:border-blue-500 hover:text-blue-400 hover:bg-blue-900/20" : "bg-white border-gray-300 text-gray-400 hover:border-blue-400 hover:text-blue-500 hover:bg-blue-50"} shadow-sm`}
          title="添加设备"
        >
          <Plus style={{ width: 13, height: 13 }} />
        </button>

        <div className={`flex flex-col items-center gap-1 mt-2 ${isDark ? "text-gray-600" : "text-gray-300"}`}>
          <ArrowRightLeft style={{ width: 12, height: 12 }} />
        </div>

        {/* Add device menu */}
        {showAddMenu && (
          <div ref={addMenuRef} className={`absolute z-50 top-1/2 left-full ml-2 -translate-y-1/2 rounded-xl border shadow-xl py-2 min-w-[220px] ${isDark ? "bg-[#2a2a2a] border-gray-700" : "bg-white border-gray-200"}`}>
            <div className={`px-3 py-1.5 ${isDark ? "text-gray-500" : "text-gray-400"}`} style={{ fontSize: 10 }}>选择设备</div>
            {onlineDevices.map((d) => {
              const DIcon = d.icon;
              const isActive = d.id === leftDeviceId || d.id === rightDeviceId;
              return (
                <button
                  key={d.id}
                  onClick={() => handleAddDevice(d.id)}
                  disabled={isActive}
                  className={`w-full flex items-center gap-2.5 px-3 py-2 transition-colors ${isActive ? (isDark ? "text-gray-600 cursor-not-allowed" : "text-gray-300 cursor-not-allowed") : (isDark ? "text-gray-300 hover:bg-gray-700" : "text-gray-700 hover:bg-gray-50")}`}
                  style={{ fontSize: 12 }}
                >
                  <div className={`w-6 h-6 rounded-md flex items-center justify-center ${isDark ? "bg-gray-700" : "bg-gray-100"}`}>
                    <DIcon style={{ width: 13, height: 13 }} />
                  </div>
                  <div className="flex-1 text-left min-w-0">
                    <div className="truncate">{d.name}</div>
                    <div className={isDark ? "text-gray-500" : "text-gray-400"} style={{ fontSize: 10 }}>{d.os} · {d.ip}</div>
                  </div>
                  {isActive && (
                    <span className={`px-1.5 py-0.5 rounded ${isDark ? "bg-gray-700 text-gray-500" : "bg-gray-100 text-gray-400"}`} style={{ fontSize: 9 }}>已添加</span>
                  )}
                  <div className="w-1.5 h-1.5 rounded-full bg-green-500 shrink-0" />
                </button>
              );
            })}
            {onlineDevices.length === 0 && (
              <div className={`px-3 py-4 text-center ${isDark ? "text-gray-500" : "text-gray-400"}`} style={{ fontSize: 12 }}>没有在线设备</div>
            )}
          </div>
        )}
      </div>

      {/* Right pane */}
      <div
        className="flex-1 flex flex-col min-w-0"
        onDragOver={(e) => { e.preventDefault(); setDragOverSide("right"); }}
        onDragLeave={() => setDragOverSide(null)}
        onDrop={() => setDragOverSide(null)}
      >
        {rightDeviceId ? (
          <FilePane
            deviceId={rightDeviceId}
            side="right"
            otherDeviceName={leftDevice?.name ?? null}
            isDark={isDark}
            onSendToOther={(fileNames) => console.log(`Send ${fileNames.join(", ")} to left pane`)}
            dragOver={dragOverSide === "right"}
          />
        ) : (
          <div className={`flex-1 flex flex-col items-center justify-center ${isDark ? "bg-[#1e1e1e]" : "bg-white"}`}>
            <div className={`w-14 h-14 rounded-2xl flex items-center justify-center mb-4 ${isDark ? "bg-gray-800" : "bg-gray-50"}`}>
              <Monitor className={`w-7 h-7 ${isDark ? "text-gray-600" : "text-gray-300"}`} />
            </div>
            <div className={isDark ? "text-gray-500" : "text-gray-400"} style={{ fontSize: 14 }}>选择设备以开始传输</div>
            <div className={`mt-1 ${isDark ? "text-gray-600" : "text-gray-300"}`} style={{ fontSize: 12 }}>点击中间的 + 号添加设备，或从侧边栏拖入</div>
            <button
              onClick={() => { setAddMenuSide("right"); setShowAddMenu(true); }}
              className={`mt-5 flex items-center gap-2 px-4 py-2 rounded-lg border transition-colors ${isDark ? "bg-[#232323] border-gray-600 text-gray-300 hover:border-blue-500 hover:text-blue-400" : "bg-gray-50 border-gray-200 text-gray-600 hover:border-blue-400 hover:text-blue-500"}`}
              style={{ fontSize: 12 }}
            >
              <Plus style={{ width: 14, height: 14 }} />
              添加设备
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function CtxItem({ icon, label, onClick, isDark, danger }: { icon: React.ReactNode; label: string; onClick: () => void; isDark: boolean; danger?: boolean }) {
  return (
    <button onClick={onClick} className={`w-full flex items-center gap-2.5 px-3 py-1.5 transition-colors ${danger ? (isDark ? "text-red-400 hover:bg-red-900/30" : "text-red-600 hover:bg-red-50") : (isDark ? "text-gray-300 hover:bg-gray-700" : "text-gray-700 hover:bg-gray-50")}`} style={{ fontSize: 12 }}>
      <span className={danger ? "" : isDark ? "text-gray-500" : "text-gray-400"}>{icon}</span>{label}
    </button>
  );
}

/* ======================== Remote Apps Tab ======================== */
function AppsTab({ device }: { device: Device }) {
  const { isDark } = useTheme();
  const [launchedApp, setLaunchedApp] = useState<typeof remoteApps[0] | null>(null);
  const [appLatency, setAppLatency] = useState(18);
  const [appElapsed, setAppElapsed] = useState(0);
  const isOnline = device.status === "online";

  useEffect(() => {
    if (!launchedApp) return;
    setAppElapsed(0);
    const timer = setInterval(() => {
      setAppElapsed((e) => e + 1);
      setAppLatency((l) => Math.max(8, Math.min(45, l + Math.floor(Math.random() * 5) - 2)));
    }, 1000);
    return () => clearInterval(timer);
  }, [launchedApp]);

  const formatTime = (s: number) => {
    const m = Math.floor(s / 60);
    const sec = s % 60;
    return `${m.toString().padStart(2, "0")}:${sec.toString().padStart(2, "0")}`;
  };

  if (!isOnline) {
    return (
      <div className={`flex items-center justify-center h-full ${isDark ? "bg-[#1a1a1a]" : "bg-[#f0f2f5]"}`}>
        <div className="text-center">
          <WifiOff className={`w-12 h-12 mx-auto mb-3 ${isDark ? "text-gray-600" : "text-gray-300"}`} />
          <div className={isDark ? "text-gray-400" : "text-gray-500"} style={{ fontSize: 16 }}>设备离线，无法启动远程应用</div>
        </div>
      </div>
    );
  }

  // Launched app full view — looks like a local app window
  if (launchedApp) {
    const AppIcon = launchedApp.icon;
    return (
      <div className="flex flex-col h-full bg-[#1e1e2e]">
        {/* App-style title bar — looks local */}
        <div className="flex items-center h-9 bg-[#2d2d3f] border-b border-white/5 shrink-0 select-none">
          {/* App icon + name */}
          <div className="flex items-center gap-2 px-3">
            <div className={`w-4 h-4 rounded ${launchedApp.color} flex items-center justify-center`}>
              <AppIcon className="w-2.5 h-2.5 text-white" />
            </div>
            <span className="text-gray-300" style={{ fontSize: 12 }}>{launchedApp.name}</span>
            <span className="text-gray-600 ml-1" style={{ fontSize: 10 }}>— {device.name} (远程)</span>
          </div>

          <div className="flex-1" />

          {/* Remote indicator pill */}
          <div className="flex items-center gap-2 mr-3">
            <div className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-blue-500/20 border border-blue-500/30" style={{ fontSize: 9 }}>
              <div className="w-1 h-1 rounded-full bg-blue-400 animate-pulse" />
              <span className="text-blue-300">远程 · {appLatency}ms</span>
            </div>
            <span className="text-gray-500" style={{ fontSize: 10 }}>{formatTime(appElapsed)}</span>
          </div>

          {/* Window controls */}
          <div className="flex items-center h-full">
            <button className="flex items-center justify-center w-10 h-full text-gray-500 hover:bg-white/5 transition-colors">
              <Minus className="w-3.5 h-3.5" />
            </button>
            <button className="flex items-center justify-center w-10 h-full text-gray-500 hover:bg-white/5 transition-colors">
              <Square className="w-3 h-3" />
            </button>
            <button
              onClick={() => setLaunchedApp(null)}
              className="flex items-center justify-center w-10 h-full text-gray-500 hover:bg-red-500 hover:text-white transition-colors"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* App content */}
        <div className="flex-1 relative overflow-hidden select-none">
          {launchedApp.screenshot ? (
            <img
              src={launchedApp.screenshot}
              alt={launchedApp.name}
              className="w-full h-full object-cover"
              draggable={false}
            />
          ) : (
            <div className="flex items-center justify-center h-full bg-[#1e1e2e]">
              <div className="text-center">
                <div className={`w-16 h-16 rounded-2xl ${launchedApp.color} flex items-center justify-center mx-auto mb-4 shadow-lg`}>
                  <AppIcon className="w-8 h-8 text-white" />
                </div>
                <div className="text-gray-300 mb-1" style={{ fontSize: 15 }}>{launchedApp.name}</div>
                <div className="text-gray-500" style={{ fontSize: 12 }}>正在启动远程应用...</div>
                <div className="mt-4 flex items-center justify-center gap-1">
                  <div className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-bounce" style={{ animationDelay: "0ms" }} />
                  <div className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-bounce" style={{ animationDelay: "150ms" }} />
                  <div className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-bounce" style={{ animationDelay: "300ms" }} />
                </div>
              </div>
            </div>
          )}

          {/* Bottom floating bar */}
          <div className="absolute bottom-3 left-1/2 -translate-x-1/2 flex items-center gap-2 px-3 py-1.5 rounded-lg bg-black/70 backdrop-blur-sm border border-white/10">
            <div className="flex items-center gap-1 text-green-400" style={{ fontSize: 10 }}>
              <div className="w-1 h-1 rounded-full bg-green-400" />
              远程应用模式
            </div>
            <div className="w-px h-3 bg-white/20" />
            <span className="text-gray-400" style={{ fontSize: 10 }}>{device.name}</span>
            <div className="w-px h-3 bg-white/20" />
            <button
              onClick={() => setLaunchedApp(null)}
              className="text-gray-400 hover:text-red-400 transition-colors"
              style={{ fontSize: 10 }}
            >
              关闭
            </button>
          </div>
        </div>
      </div>
    );
  }

  // App grid list
  const runningApps = remoteApps.filter((a) => a.running);
  const availableApps = remoteApps.filter((a) => !a.running);

  return (
    <div className={`h-full overflow-y-auto p-5 ${isDark ? "bg-[#1a1a1a]" : "bg-[#f0f2f5]"}`}>
      <div className="max-w-4xl mx-auto">
        {/* Explain */}
        <div className={`flex items-start gap-3 p-3.5 rounded-lg border mb-5 ${isDark ? "bg-blue-900/20 border-blue-800" : "bg-blue-50 border-blue-100"}`}>
          <AppWindow className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
          <div>
            <div className={isDark ? "text-blue-400" : "text-blue-700"} style={{ fontSize: 13 }}>远程应用模式</div>
            <div className={isDark ? "text-gray-400 mt-0.5" : "text-gray-500 mt-0.5"} style={{ fontSize: 12 }}>
              仅显示远程设备上的单个应用窗口，看起来就像本地运行的程序。无需查看整个远程桌面，延迟更低，体验更流畅。
            </div>
          </div>
        </div>

        {/* Running apps */}
        {runningApps.length > 0 && (
          <div className="mb-6">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-1.5 h-1.5 rounded-full bg-green-500" />
              <span className={isDark ? "text-gray-400" : "text-gray-600"} style={{ fontSize: 13 }}>正在运行 ({runningApps.length})</span>
            </div>
            <div className="grid grid-cols-3 gap-3">
              {runningApps.map((app) => {
                const AppIcon = app.icon;
                return (
                  <div
                    key={app.id}
                    onClick={() => setLaunchedApp(app)}
                    className={`group relative p-4 rounded-xl border shadow-xs cursor-pointer transition-all ${isDark ? "bg-[#232323] border-gray-700 hover:border-blue-500 hover:shadow-md" : "bg-white border-gray-200 hover:border-blue-300 hover:shadow-md"}`}
                  >
                    {/* Thumbnail preview */}
                    {app.screenshot && (
                      <div className={`w-full h-24 rounded-lg overflow-hidden mb-3 border ${isDark ? "border-gray-700 bg-[#1a1a1a]" : "border-gray-100 bg-gray-50"}`}>
                        <img
                          src={app.screenshot}
                          alt={app.name}
                          className="w-full h-full object-cover opacity-90 group-hover:opacity-100 transition-opacity"
                          draggable={false}
                        />
                      </div>
                    )}
                    <div className="flex items-center gap-3">
                      <div className={`w-8 h-8 rounded-lg ${app.color} flex items-center justify-center shrink-0 shadow-sm`}>
                        <AppIcon className="w-4 h-4 text-white" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className={`font-medium truncate ${isDark ? "text-gray-200" : "text-gray-800"}`} style={{ fontSize: 13 }}>{app.name}</div>
                        <div className={isDark ? "text-gray-500" : "text-gray-400"} style={{ fontSize: 11 }}>{app.description}</div>
                      </div>
                    </div>
                    {/* Running indicator */}
                    <div className={`absolute top-2.5 right-2.5 flex items-center gap-1 px-1.5 py-0.5 rounded-full border ${isDark ? "bg-green-900/30 border-green-700" : "bg-green-50 border-green-200"}`} style={{ fontSize: 9 }}>
                      <div className="w-1 h-1 rounded-full bg-green-500" />
                      <span className="text-green-600">运行中</span>
                    </div>
                    {/* Hover overlay */}
                    <div className="absolute inset-0 flex items-center justify-center rounded-xl bg-blue-600/0 group-hover:bg-blue-600/5 transition-colors">
                      <div className="opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-blue-600 text-white shadow-lg" style={{ fontSize: 12 }}>
                        <ExternalLink className="w-3 h-3" />
                        打开应用
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Available apps */}
        <div>
          <div className="flex items-center gap-2 mb-3">
            <span className={isDark ? "text-gray-400" : "text-gray-500"} style={{ fontSize: 13 }}>可启动 ({availableApps.length})</span>
          </div>
          <div className="grid grid-cols-4 gap-2.5">
            {availableApps.map((app) => {
              const AppIcon = app.icon;
              return (
                <div
                  key={app.id}
                  onClick={() => setLaunchedApp(app)}
                  className={`flex items-center gap-2.5 p-3 rounded-lg border cursor-pointer transition-all group ${isDark ? "bg-[#232323] border-gray-700 hover:border-gray-600 hover:shadow-sm" : "bg-white border-gray-200 hover:border-gray-300 hover:shadow-sm"}`}
                >
                  <div className={`w-8 h-8 rounded-lg ${app.color} flex items-center justify-center shrink-0 opacity-80 group-hover:opacity-100 transition-opacity`}>
                    <AppIcon className="w-4 h-4 text-white" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className={`truncate ${isDark ? "text-gray-300" : "text-gray-700"}`} style={{ fontSize: 12 }}>{app.name}</div>
                    <div className={isDark ? "text-gray-500" : "text-gray-400"} style={{ fontSize: 10 }}>{app.description}</div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ======================== Performance Monitoring Footer ======================== */
function PerformanceFooter({ device }: { device: Device }) {
  const { isDark } = useTheme();
  const [cpu, setCpu] = useState(device.cpu ?? 0);
  const [ram, setRam] = useState(device.ram ?? 0);
  const [disk] = useState(device.disk ?? 0);
  const [netUp, setNetUp] = useState(2.4);
  const [netDown, setNetDown] = useState(8.7);

  useEffect(() => {
    const timer = setInterval(() => {
      setCpu((v) => Math.max(5, Math.min(95, v + Math.floor(Math.random() * 9) - 4)));
      setRam((v) => Math.max(30, Math.min(90, v + Math.floor(Math.random() * 5) - 2)));
      setNetUp((v) => Math.max(0.5, Math.min(12, +(v + (Math.random() * 2 - 1)).toFixed(1))));
      setNetDown((v) => Math.max(1, Math.min(25, +(v + (Math.random() * 3 - 1.5)).toFixed(1))));
    }, 2000);
    return () => clearInterval(timer);
  }, []);

  const getBarColor = (value: number) => {
    if (value > 85) return "bg-red-500";
    if (value > 65) return "bg-yellow-500";
    return "bg-green-500";
  };

  const getTextColor = (value: number) => {
    if (value > 85) return isDark ? "text-red-400" : "text-red-500";
    if (value > 65) return isDark ? "text-yellow-400" : "text-yellow-600";
    return isDark ? "text-green-400" : "text-green-600";
  };

  return (
    <div className={`shrink-0 flex items-center gap-6 px-5 py-1.5 border-t ${isDark ? "bg-[#1e1e1e] border-gray-700" : "bg-white border-gray-200"}`}>
      {/* CPU */}
      <div className="flex items-center gap-2">
        <Cpu style={{ width: 12, height: 12 }} className={isDark ? "text-gray-500" : "text-gray-400"} />
        <span className={isDark ? "text-gray-500" : "text-gray-400"} style={{ fontSize: 10 }}>CPU</span>
        <div className={`w-16 h-1.5 rounded-full overflow-hidden ${isDark ? "bg-gray-700" : "bg-gray-200"}`}>
          <div className={`h-full rounded-full transition-all duration-1000 ${getBarColor(cpu)}`} style={{ width: `${cpu}%` }} />
        </div>
        <span className={getTextColor(cpu)} style={{ fontSize: 10 }}>{cpu}%</span>
      </div>

      {/* RAM */}
      <div className="flex items-center gap-2">
        <MemoryStick style={{ width: 12, height: 12 }} className={isDark ? "text-gray-500" : "text-gray-400"} />
        <span className={isDark ? "text-gray-500" : "text-gray-400"} style={{ fontSize: 10 }}>RAM</span>
        <div className={`w-16 h-1.5 rounded-full overflow-hidden ${isDark ? "bg-gray-700" : "bg-gray-200"}`}>
          <div className={`h-full rounded-full transition-all duration-1000 ${getBarColor(ram)}`} style={{ width: `${ram}%` }} />
        </div>
        <span className={getTextColor(ram)} style={{ fontSize: 10 }}>{ram}%</span>
      </div>

      {/* Disk */}
      <div className="flex items-center gap-2">
        <HardDrive style={{ width: 12, height: 12 }} className={isDark ? "text-gray-500" : "text-gray-400"} />
        <span className={isDark ? "text-gray-500" : "text-gray-400"} style={{ fontSize: 10 }}>DISK</span>
        <div className={`w-16 h-1.5 rounded-full overflow-hidden ${isDark ? "bg-gray-700" : "bg-gray-200"}`}>
          <div className={`h-full rounded-full transition-all duration-1000 ${getBarColor(disk)}`} style={{ width: `${disk}%` }} />
        </div>
        <span className={getTextColor(disk)} style={{ fontSize: 10 }}>{disk}%</span>
      </div>

      {/* Separator */}
      <div className={`h-3 w-px ${isDark ? "bg-gray-700" : "bg-gray-200"}`} />

      {/* Network */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1.5">
          <Upload style={{ width: 10, height: 10 }} className={isDark ? "text-gray-500" : "text-gray-400"} />
          <span className={isDark ? "text-gray-400" : "text-gray-500"} style={{ fontSize: 10 }}>{netUp} MB/s</span>
        </div>
        <div className="flex items-center gap-1.5">
          <Download style={{ width: 10, height: 10 }} className={isDark ? "text-gray-500" : "text-gray-400"} />
          <span className={isDark ? "text-gray-400" : "text-gray-500"} style={{ fontSize: 10 }}>{netDown} MB/s</span>
        </div>
      </div>

      <div className="flex-1" />

      {/* Ping */}
      {device.ping !== null && (
        <div className="flex items-center gap-1.5">
          <Activity style={{ width: 11, height: 11 }} className={device.ping < 30 ? "text-green-500" : "text-yellow-500"} />
          <span className={device.ping < 30 ? "text-green-600" : "text-yellow-600"} style={{ fontSize: 10 }}>{device.ping}ms</span>
        </div>
      )}

      {/* TLS */}
      <div className="flex items-center gap-1">
        <Lock style={{ width: 10, height: 10 }} className="text-green-500" />
        <span className="text-green-600" style={{ fontSize: 10 }}>TLS 1.3</span>
      </div>
    </div>
  );
}

/* ======================== Shared sub-components ======================== */

function ResourcePill({ label, value, color }: { label: string; value: number; color: string }) {
  const { isDark } = useTheme();
  const colorMap: Record<string, string> = {
    blue: isDark ? "text-blue-400 bg-blue-900/30" : "text-blue-600 bg-blue-50",
    purple: isDark ? "text-purple-400 bg-purple-900/30" : "text-purple-600 bg-purple-50",
    green: isDark ? "text-green-400 bg-green-900/30" : "text-green-600 bg-green-50",
  };
  const barColor: Record<string, string> = {
    blue: "bg-blue-500",
    purple: "bg-purple-500",
    green: "bg-green-500",
  };
  return (
    <div className="flex items-center gap-1.5">
      <span className={isDark ? "text-gray-500" : "text-gray-400"} style={{ fontSize: 10 }}>{label}</span>
      <div className={`w-14 h-1 rounded-full ${isDark ? "bg-gray-700" : "bg-gray-200"}`}>
        <div className={`h-full rounded-full ${barColor[color]}`} style={{ width: `${value}%`, opacity: 0.75 }} />
      </div>
      <span className={`${colorMap[color]} px-1 rounded`} style={{ fontSize: 10 }}>{value}%</span>
    </div>
  );
}

function ToolbarBtn({
  icon, label, onClick, active, danger,
}: {
  icon: React.ReactNode; label: string; onClick?: () => void; active?: boolean; danger?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      title={label}
      className={`flex items-center gap-1.5 px-2 py-1 rounded-md transition-colors ${
        danger ? "text-red-400/70 hover:bg-red-500/10 hover:text-red-400"
        : active === false ? "text-gray-500 hover:bg-white/5 hover:text-gray-300"
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