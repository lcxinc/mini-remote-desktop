import { useState, useRef, useEffect } from "react";
import {
  Upload,
  Download,
  FileText,
  FileImage,
  FileVideo,
  FileArchive,
  FileCode,
  File,
  Monitor,
  Laptop,
  Server,
  CheckCircle2,
  Pause,
  Play,
  X,
  FolderOpen,
  ArrowUpFromLine,
  ArrowDownToLine,
  Trash2,
  Clock,
  Search,
  RotateCcw,
} from "lucide-react";
import { useTheme } from "./ThemeContext";

type TransferStatus = "active" | "paused" | "done" | "error";
type TransferDirection = "send" | "receive";

interface TransferItem {
  id: string;
  name: string;
  size: string;
  totalBytes: number;
  transferredBytes: number;
  progress: number;
  status: TransferStatus;
  direction: TransferDirection;
  localDevice: string;
  remoteDevice: string;
  remoteDeviceIcon: typeof Monitor;
  speed?: string;
  eta?: string;
  time: string;
  fileIcon: typeof File;
  savePath?: string;
}

const transferData: TransferItem[] = [
  {
    id: "1",
    name: "project-backup.zip",
    size: "2.1 GB",
    totalBytes: 2254857830,
    transferredBytes: 1510754746,
    progress: 67,
    status: "active",
    direction: "send",
    localDevice: "本机",
    remoteDevice: "办公室电脑",
    remoteDeviceIcon: Monitor,
    speed: "12.4 MB/s",
    eta: "约 58 秒",
    time: "14:32",
    fileIcon: FileArchive,
    savePath: "C:\\Users\\Admin\\Downloads",
  },
  {
    id: "2",
    name: "design-assets-v3.fig",
    size: "340 MB",
    totalBytes: 356515840,
    transferredBytes: 142606336,
    progress: 40,
    status: "active",
    direction: "receive",
    localDevice: "本机",
    remoteDevice: "设计工作站",
    remoteDeviceIcon: Laptop,
    speed: "8.7 MB/s",
    eta: "约 23 秒",
    time: "14:28",
    fileIcon: FileImage,
    savePath: "~/Downloads",
  },
  {
    id: "3",
    name: "database-dump.sql",
    size: "890 MB",
    totalBytes: 933232640,
    transferredBytes: 317299098,
    progress: 34,
    status: "paused",
    direction: "send",
    localDevice: "本机",
    remoteDevice: "Linux 服务器",
    remoteDeviceIcon: Server,
    time: "13:15",
    fileIcon: FileCode,
    savePath: "/home/admin/backups",
  },
  {
    id: "4",
    name: "weekly-report.docx",
    size: "4.2 MB",
    totalBytes: 4404019,
    transferredBytes: 1761608,
    progress: 40,
    status: "error",
    direction: "receive",
    localDevice: "本机",
    remoteDevice: "办公室电脑",
    remoteDeviceIcon: Monitor,
    time: "13:02",
    fileIcon: FileText,
    savePath: "~/Documents",
  },
  {
    id: "5",
    name: "presentation-final.pptx",
    size: "18 MB",
    totalBytes: 18874368,
    transferredBytes: 18874368,
    progress: 100,
    status: "done",
    direction: "send",
    localDevice: "本机",
    remoteDevice: "设计工作站",
    remoteDeviceIcon: Laptop,
    time: "12:45",
    fileIcon: FileText,
    savePath: "~/Documents/Work",
  },
  {
    id: "6",
    name: "demo-video.mp4",
    size: "1.4 GB",
    totalBytes: 1503238553,
    transferredBytes: 1503238553,
    progress: 100,
    status: "done",
    direction: "receive",
    localDevice: "本机",
    remoteDevice: "Linux 服务器",
    remoteDeviceIcon: Server,
    time: "11:30",
    fileIcon: FileVideo,
    savePath: "~/Videos",
  },
  {
    id: "7",
    name: "config-backup.tar.gz",
    size: "56 MB",
    totalBytes: 58720256,
    transferredBytes: 58720256,
    progress: 100,
    status: "done",
    direction: "send",
    localDevice: "本机",
    remoteDevice: "Linux 服务器",
    remoteDeviceIcon: Server,
    time: "10:22",
    fileIcon: FileArchive,
    savePath: "/etc/backup",
  },
  {
    id: "8",
    name: "screenshot-2026-03-04.png",
    size: "3.8 MB",
    totalBytes: 3984588,
    transferredBytes: 3984588,
    progress: 100,
    status: "done",
    direction: "receive",
    localDevice: "本机",
    remoteDevice: "办公室电脑",
    remoteDeviceIcon: Monitor,
    time: "09:55",
    fileIcon: FileImage,
    savePath: "~/Pictures",
  },
  {
    id: "9",
    name: "logs-archive.zip",
    size: "234 MB",
    totalBytes: 245366784,
    transferredBytes: 245366784,
    progress: 100,
    status: "done",
    direction: "send",
    localDevice: "本机",
    remoteDevice: "设计工作站",
    remoteDeviceIcon: Laptop,
    time: "昨天 18:30",
    fileIcon: FileArchive,
    savePath: "~/Downloads",
  },
];

function formatBytes(bytes: number): string {
  if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(1) + " GB";
  if (bytes >= 1048576) return (bytes / 1048576).toFixed(0) + " MB";
  return (bytes / 1024).toFixed(0) + " KB";
}

interface TransferModalProps {
  open: boolean;
  onClose: () => void;
}

export function TransferModal({ open, onClose }: TransferModalProps) {
  const { isDark } = useTheme();
  const [filter, setFilter] = useState<"all" | "send" | "receive">("all");
  const [searchQuery, setSearchQuery] = useState("");
  const backdropRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [open, onClose]);

  if (!open) return null;

  const activeTransfers = transferData.filter(
    (t) => t.status === "active" || t.status === "paused" || t.status === "error"
  );
  const completedTransfers = transferData.filter((t) => t.status === "done");

  const filterItems = (items: TransferItem[]) =>
    items
      .filter((t) => filter === "all" || t.direction === filter)
      .filter(
        (t) =>
          !searchQuery ||
          t.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
          t.remoteDevice.toLowerCase().includes(searchQuery.toLowerCase())
      );

  const filteredActive = filterItems(activeTransfers);
  const filteredCompleted = filterItems(completedTransfers);

  const card = isDark
    ? "bg-[#2a2a2a] border-gray-700"
    : "bg-white border-gray-200 shadow-xs";
  const textSecondary = isDark ? "text-gray-400" : "text-gray-500";
  const textTertiary = isDark ? "text-gray-500" : "text-gray-400";

  const totalActive = activeTransfers.length;
  const totalSending = transferData.filter((t) => t.direction === "send" && (t.status === "active" || t.status === "paused")).length;
  const totalReceiving = transferData.filter((t) => t.direction === "receive" && (t.status === "active" || t.status === "paused")).length;

  const directionBadge = (direction: TransferDirection, compact = false) => {
    const isSend = direction === "send";
    return (
      <span
        className={`inline-flex items-center gap-1 rounded-full ${
          compact ? "px-1.5 py-0.5" : "px-2 py-0.5"
        } ${
          isSend
            ? isDark
              ? "bg-blue-900/30 text-blue-400"
              : "bg-blue-50 text-blue-600 border border-blue-100"
            : isDark
            ? "bg-emerald-900/30 text-emerald-400"
            : "bg-emerald-50 text-emerald-600 border border-emerald-100"
        }`}
        style={{ fontSize: 11 }}
      >
        {isSend ? (
          <ArrowUpFromLine style={{ width: 10, height: 10 }} />
        ) : (
          <ArrowDownToLine style={{ width: 10, height: 10 }} />
        )}
        {!compact && (isSend ? "发送" : "接收")}
      </span>
    );
  };

  const flowIndicator = (item: TransferItem) => {
    const isSend = item.direction === "send";
    const DevIcon = item.remoteDeviceIcon;
    return (
      <div className="flex items-center gap-1.5" style={{ fontSize: 11 }}>
        <span className={isDark ? "text-gray-300" : "text-gray-600"}>
          {isSend ? "本机" : item.remoteDevice}
        </span>
        <span className={`${isSend ? (isDark ? "text-blue-400" : "text-blue-500") : (isDark ? "text-emerald-400" : "text-emerald-500")}`}>→</span>
        <div className="flex items-center gap-1">
          <DevIcon style={{ width: 11, height: 11 }} className={textTertiary} />
          <span className={isDark ? "text-gray-300" : "text-gray-600"}>
            {isSend ? item.remoteDevice : "本机"}
          </span>
        </div>
      </div>
    );
  };

  const renderActiveItem = (t: TransferItem) => {
    const Icon = t.fileIcon;
    const isSend = t.direction === "send";
    const statusColor =
      t.status === "active"
        ? "bg-blue-500"
        : t.status === "paused"
        ? isDark
          ? "bg-yellow-500"
          : "bg-amber-400"
        : "bg-red-500";

    const statusGradient =
      t.status === "active"
        ? isDark ? "linear-gradient(90deg, #2563eb, #3b82f6)" : "linear-gradient(90deg, #3b82f6, #60a5fa)"
        : t.status === "paused"
        ? isDark ? "linear-gradient(90deg, #eab308, #f59e0b)" : "linear-gradient(90deg, #f59e0b, #fbbf24)"
        : isDark ? "linear-gradient(90deg, #dc2626, #ef4444)" : "linear-gradient(90deg, #ef4444, #f87171)";

    const statusGlow =
      t.status === "active"
        ? "0 0 8px rgba(59,130,246,0.35)"
        : t.status === "paused"
        ? "0 0 8px rgba(245,158,11,0.35)"
        : "0 0 8px rgba(239,68,68,0.3)";

    return (
      <div
        key={t.id}
        className={`group relative rounded-xl border p-3.5 transition-colors ${card} ${
          isDark ? "hover:border-gray-600" : "hover:border-gray-300"
        }`}
      >
        {/* Left accent line */}
        <div
          className={`absolute left-0 top-2.5 bottom-2.5 w-[3px] rounded-r-full ${
            isSend
              ? isDark ? "bg-blue-500" : "bg-blue-400"
              : isDark ? "bg-emerald-500" : "bg-emerald-400"
          }`}
        />

        <div className="flex items-start gap-3 pl-2">
          {/* File icon */}
          <div
            className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${
              isSend
                ? isDark ? "bg-blue-900/30" : "bg-blue-50"
                : isDark ? "bg-emerald-900/30" : "bg-emerald-50"
            }`}
          >
            <Icon
              style={{ width: 18, height: 18 }}
              className={
                isSend
                  ? isDark ? "text-blue-400" : "text-blue-500"
                  : isDark ? "text-emerald-400" : "text-emerald-500"
              }
            />
          </div>

          {/* Info */}
          <div className="flex-1 min-w-0">
            {/* Row 1: name + badges + actions */}
            <div className="flex items-center gap-2 mb-0.5">
              <span
                className={`truncate ${isDark ? "text-gray-200" : "text-gray-800"}`}
                style={{ fontSize: 13 }}
              >
                {t.name}
              </span>
              {directionBadge(t.direction)}
              {t.status === "paused" && (
                <span
                  className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full ${
                    isDark ? "bg-yellow-900/30 text-yellow-400" : "bg-amber-50 text-amber-600 border border-amber-100"
                  }`}
                  style={{ fontSize: 10 }}
                >
                  已暂停
                </span>
              )}
              {t.status === "error" && (
                <span
                  className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full ${
                    isDark ? "bg-red-900/30 text-red-400" : "bg-red-50 text-red-600 border border-red-100"
                  }`}
                  style={{ fontSize: 10 }}
                >
                  传输失败
                </span>
              )}
              <div className="flex-1" />
              {/* Actions */}
              <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
                {t.status === "active" && (
                  <button
                    className={`p-1 rounded-md transition-colors ${
                      isDark ? "text-gray-400 hover:text-yellow-400 hover:bg-yellow-900/20" : "text-gray-400 hover:text-amber-600 hover:bg-amber-50"
                    }`}
                    title="暂停"
                  >
                    <Pause style={{ width: 12, height: 12 }} />
                  </button>
                )}
                {t.status === "paused" && (
                  <button
                    className={`p-1 rounded-md transition-colors ${
                      isDark ? "text-gray-400 hover:text-blue-400 hover:bg-blue-900/20" : "text-gray-400 hover:text-blue-600 hover:bg-blue-50"
                    }`}
                    title="继续"
                  >
                    <Play style={{ width: 12, height: 12 }} />
                  </button>
                )}
                {t.status === "error" && (
                  <button
                    className={`p-1 rounded-md transition-colors ${
                      isDark ? "text-gray-400 hover:text-blue-400 hover:bg-blue-900/20" : "text-gray-400 hover:text-blue-600 hover:bg-blue-50"
                    }`}
                    title="重试"
                  >
                    <RotateCcw style={{ width: 12, height: 12 }} />
                  </button>
                )}
                <button
                  className={`p-1 rounded-md transition-colors ${
                    isDark ? "text-gray-400 hover:text-red-400 hover:bg-red-900/20" : "text-gray-400 hover:text-red-500 hover:bg-red-50"
                  }`}
                  title="取消传输"
                >
                  <X style={{ width: 12, height: 12 }} />
                </button>
              </div>
            </div>

            {/* Row 2: flow direction + meta inline */}
            <div className="flex items-center gap-3 mb-1.5">
              {flowIndicator(t)}
              <span className={isDark ? "text-gray-600" : "text-gray-300"} style={{ fontSize: 11 }}>·</span>
              <span className={textTertiary} style={{ fontSize: 11 }}>
                {formatBytes(t.transferredBytes)} / {t.size}
              </span>
              {t.speed && t.status === "active" && (
                <>
                  <span className={isDark ? "text-gray-600" : "text-gray-300"} style={{ fontSize: 11 }}>·</span>
                  <span className={isDark ? "text-blue-400" : "text-blue-500"} style={{ fontSize: 11 }}>
                    {t.speed}
                  </span>
                </>
              )}
              {t.eta && t.status === "active" && (
                <>
                  <span className={isDark ? "text-gray-600" : "text-gray-300"} style={{ fontSize: 11 }}>·</span>
                  <span className={textTertiary} style={{ fontSize: 11 }}>
                    {t.eta}
                  </span>
                </>
              )}
              <div className="flex-1" />
              <span className={textTertiary} style={{ fontSize: 11 }}>
                {t.time}
              </span>
            </div>

            {/* Row 3: progress bar */}
            <div className="flex items-center gap-2.5">
              <div
                className={`flex-1 h-1.5 rounded-full overflow-hidden ${
                  isDark ? "bg-gray-700/80" : "bg-gray-100"
                }`}
                style={{ boxShadow: isDark ? "inset 0 1px 2px rgba(0,0,0,0.3)" : "inset 0 1px 2px rgba(0,0,0,0.06)" }}
              >
                <div
                  className="h-full rounded-full transition-all duration-500 relative overflow-hidden"
                  style={{
                    width: `${t.progress}%`,
                    background: statusGradient,
                    boxShadow: statusGlow,
                  }}
                >
                  {t.status === "active" && (
                    <div
                      className="absolute inset-0"
                      style={{
                        background: "linear-gradient(90deg, transparent 0%, rgba(255,255,255,0.25) 50%, transparent 100%)",
                        backgroundSize: "200% 100%",
                        animation: "progressShimmer 2s ease-in-out infinite",
                      }}
                    />
                  )}
                </div>
              </div>
              <span className={`tabular-nums ${textSecondary}`} style={{ fontSize: 11, minWidth: 32, textAlign: "right" }}>
                {t.progress}%
              </span>
            </div>
          </div>
        </div>
      </div>
    );
  };

  const renderCompletedItem = (t: TransferItem) => {
    const Icon = t.fileIcon;
    const isSend = t.direction === "send";
    const DevIcon = t.remoteDeviceIcon;

    return (
      <div
        key={t.id}
        className={`group flex items-center gap-3 px-3.5 py-2.5 rounded-xl border transition-colors ${card} ${
          isDark ? "hover:border-gray-600" : "hover:border-gray-300"
        }`}
      >
        {/* File icon */}
        <div
          className={`w-7 h-7 rounded-md flex items-center justify-center shrink-0 ${
            isDark ? "bg-gray-800" : "bg-gray-50"
          }`}
        >
          <Icon style={{ width: 14, height: 14 }} className={textTertiary} />
        </div>

        {/* Name + flow */}
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span
              className={`truncate ${isDark ? "text-gray-200" : "text-gray-700"}`}
              style={{ fontSize: 12 }}
            >
              {t.name}
            </span>
            {directionBadge(t.direction, true)}
          </div>
          <div className="flex items-center gap-1.5 mt-0.5">
            <span className={textTertiary} style={{ fontSize: 10 }}>
              {isSend ? "本机" : t.remoteDevice}
            </span>
            <span className={isDark ? "text-gray-600" : "text-gray-300"} style={{ fontSize: 10 }}>→</span>
            <DevIcon style={{ width: 9, height: 9 }} className={textTertiary} />
            <span className={textTertiary} style={{ fontSize: 10 }}>
              {isSend ? t.remoteDevice : "本机"}
            </span>
            <span className={isDark ? "text-gray-600" : "text-gray-300"} style={{ fontSize: 10 }}>·</span>
            <span className={textTertiary} style={{ fontSize: 10 }}>{t.size}</span>
          </div>
        </div>

        {/* Time */}
        <span className={`shrink-0 ${textTertiary}`} style={{ fontSize: 11 }}>
          {t.time}
        </span>

        {/* Status */}
        <CheckCircle2 style={{ width: 13, height: 13 }} className="text-emerald-500 shrink-0" />

        {/* Actions */}
        <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
          {t.savePath && (
            <button
              className={`flex items-center gap-1 px-1.5 py-0.5 rounded-md transition-colors ${
                isDark
                  ? "text-gray-400 hover:text-gray-200 hover:bg-gray-700"
                  : "text-gray-400 hover:text-gray-700 hover:bg-gray-100"
              }`}
              title={`打开位置: ${t.savePath}`}
              style={{ fontSize: 10 }}
            >
              <FolderOpen style={{ width: 11, height: 11 }} />
              打开位置
            </button>
          )}
          <button
            className={`p-1 rounded-md transition-colors ${
              isDark ? "text-gray-500 hover:text-red-400 hover:bg-red-900/20" : "text-gray-400 hover:text-red-500 hover:bg-red-50"
            }`}
            title="删除记录"
          >
            <Trash2 style={{ width: 11, height: 11 }} />
          </button>
        </div>
      </div>
    );
  };

  return (
    <div
      ref={backdropRef}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm"
      onClick={(e) => { if (e.target === backdropRef.current) onClose(); }}
    >
      <div
        className={`w-[680px] max-h-[80vh] rounded-xl border flex flex-col overflow-hidden ${
          isDark ? "bg-[#1e1e1e] border-gray-700 shadow-[0_12px_40px_rgba(0,0,0,0.5)]" : "bg-[#f7f8fa] border-gray-200/80 shadow-[0_12px_40px_rgba(0,0,0,0.12),0_4px_12px_rgba(0,0,0,0.06)]"
        }`}
        style={{ animation: "slideInFromLeft 200ms ease-out" }}
      >
        {/* Unified header bar */}
        <div
          className={`flex items-center gap-3 px-4 py-3 border-b shrink-0 ${
            isDark ? "bg-[#232323] border-gray-700" : "bg-white border-gray-200"
          }`}
        >
          {/* Title + stats */}
          <span className={isDark ? "text-gray-100" : "text-gray-800"} style={{ fontSize: 14 }}>
            传输管理
          </span>

          <div className="flex items-center gap-1.5">
            <span
              className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full ${
                isDark ? "bg-blue-900/30 text-blue-400" : "bg-blue-50 text-blue-600"
              }`}
              style={{ fontSize: 10 }}
            >
              <div className="w-1 h-1 rounded-full bg-blue-500 animate-pulse" />
              {totalActive}
            </span>
            <span
              className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full ${
                isDark ? "bg-gray-700 text-gray-400" : "bg-gray-100 text-gray-500"
              }`}
              style={{ fontSize: 10 }}
            >
              <ArrowUpFromLine style={{ width: 9, height: 9 }} />
              {totalSending}
            </span>
            <span
              className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full ${
                isDark ? "bg-gray-700 text-gray-400" : "bg-gray-100 text-gray-500"
              }`}
              style={{ fontSize: 10 }}
            >
              <ArrowDownToLine style={{ width: 9, height: 9 }} />
              {totalReceiving}
            </span>
          </div>

          {/* Divider */}
          <div className={`w-px h-4 ${isDark ? "bg-gray-700" : "bg-gray-200"}`} />

          {/* Filter tabs */}
          <div className="flex items-center gap-0.5">
            {(["all", "send", "receive"] as const).map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-2.5 py-1 rounded-md transition-colors ${
                  filter === f
                    ? isDark
                      ? "bg-gray-700 text-gray-200"
                      : "bg-gray-100 text-gray-800 shadow-sm"
                    : isDark
                    ? "text-gray-400 hover:text-gray-200 hover:bg-gray-800"
                    : "text-gray-500 hover:text-gray-700 hover:bg-gray-50"
                }`}
                style={{ fontSize: 12 }}
              >
                {f === "all" ? "全部" : f === "send" ? "发送" : "接收"}
              </button>
            ))}
          </div>

          <div className="flex-1" />

          {/* Search */}
          <div
            className={`flex items-center gap-1.5 px-2 py-1 rounded-md border ${
              isDark ? "bg-[#2a2a2a] border-gray-600" : "bg-gray-50 border-gray-200"
            }`}
          >
            <Search style={{ width: 11, height: 11 }} className={textTertiary} />
            <input
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="搜索..."
              className={`bg-transparent outline-none placeholder-gray-400 w-28 ${
                isDark ? "text-gray-200" : "text-gray-700"
              }`}
              style={{ fontSize: 11 }}
            />
          </div>

          {/* Close */}
          <button
            onClick={onClose}
            className={`p-1.5 rounded-md transition-colors ${
              isDark ? "text-gray-400 hover:text-gray-200 hover:bg-gray-700" : "text-gray-400 hover:text-gray-700 hover:bg-gray-100"
            }`}
            title="关闭"
          >
            <X style={{ width: 14, height: 14 }} />
          </button>
        </div>

        {/* Scrollable content */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {/* Active / In-progress section */}
          {filteredActive.length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-2">
                <div className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse" />
                <span className={isDark ? "text-gray-300" : "text-gray-700"} style={{ fontSize: 12 }}>
                  传输中
                </span>
                <span
                  className={`px-1.5 py-0.5 rounded-full ${isDark ? "bg-gray-700 text-gray-400" : "bg-gray-100 text-gray-500"}`}
                  style={{ fontSize: 10 }}
                >
                  {filteredActive.length}
                </span>
                <div className="flex-1" />
                <button
                  className={`flex items-center gap-1 px-2 py-0.5 rounded-md transition-colors ${
                    isDark ? "text-red-400 hover:bg-red-900/20" : "text-red-500 hover:bg-red-50"
                  }`}
                  style={{ fontSize: 11 }}
                >
                  <X style={{ width: 11, height: 11 }} />
                  全部取消
                </button>
              </div>
              <div className="space-y-2">
                {filteredActive.map(renderActiveItem)}
              </div>
            </div>
          )}

          {/* Completed section */}
          {filteredCompleted.length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-2">
                <CheckCircle2 style={{ width: 12, height: 12 }} className="text-emerald-500" />
                <span className={isDark ? "text-gray-300" : "text-gray-700"} style={{ fontSize: 12 }}>
                  已完成
                </span>
                <span
                  className={`px-1.5 py-0.5 rounded-full ${isDark ? "bg-gray-700 text-gray-400" : "bg-gray-100 text-gray-500"}`}
                  style={{ fontSize: 10 }}
                >
                  {filteredCompleted.length}
                </span>
                <div className="flex-1" />
                <button
                  className={`flex items-center gap-1 px-2 py-0.5 rounded-md transition-colors ${
                    isDark ? "text-gray-400 hover:bg-gray-700" : "text-gray-500 hover:bg-gray-100"
                  }`}
                  style={{ fontSize: 11 }}
                >
                  <Trash2 style={{ width: 11, height: 11 }} />
                  清空记录
                </button>
              </div>
              <div className="space-y-1.5">
                {filteredCompleted.map(renderCompletedItem)}
              </div>
            </div>
          )}

          {/* Empty state */}
          {filteredActive.length === 0 && filteredCompleted.length === 0 && (
            <div className="flex flex-col items-center justify-center py-16">
              <div
                className={`w-14 h-14 rounded-2xl flex items-center justify-center mb-3 ${
                  isDark ? "bg-gray-800" : "bg-gray-100"
                }`}
              >
                <Upload style={{ width: 22, height: 22 }} className={textTertiary} />
              </div>
              <p className={textSecondary} style={{ fontSize: 13 }}>
                暂无传输记录
              </p>
              <p className={textTertiary} style={{ fontSize: 11 }}>
                在设备详情中发起文件传输后，任务将显示在此处
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}