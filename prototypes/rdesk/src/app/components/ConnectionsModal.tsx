import { useState, useEffect } from "react";
import {
  Monitor,
  Laptop,
  Server,
  Search,
  Calendar,
  Clock,
  Download,
  Trash2,
  ArrowUpRight,
  ArrowDownLeft,
  CheckCircle,
  XCircle,
  X,
  History,
} from "lucide-react";
import { useTheme } from "./ThemeContext";

const sessions = [
  {
    id: "1",
    device: "办公室电脑",
    deviceId: "821 456 789",
    icon: Monitor,
    type: "outgoing",
    date: "2026-03-04",
    start: "09:15",
    end: "11:42",
    duration: "2小时27分",
    status: "completed",
    transferred: "1.2 GB",
    quality: 92,
  },
  {
    id: "2",
    device: "家用 MacBook",
    deviceId: "334 902 115",
    icon: Laptop,
    type: "incoming",
    date: "2026-03-04",
    start: "08:05",
    end: "08:48",
    duration: "43分钟",
    status: "completed",
    transferred: "234 MB",
    quality: 88,
  },
  {
    id: "3",
    device: "Linux 服务器",
    deviceId: "567 234 891",
    icon: Server,
    type: "outgoing",
    date: "2026-03-03",
    start: "16:30",
    end: "16:35",
    duration: "5分钟",
    status: "failed",
    transferred: "0 MB",
    quality: 0,
  },
  {
    id: "4",
    device: "办公室电脑",
    deviceId: "821 456 789",
    icon: Monitor,
    type: "outgoing",
    date: "2026-03-03",
    start: "13:00",
    end: "15:22",
    duration: "2小时22分",
    status: "completed",
    transferred: "892 MB",
    quality: 95,
  },
  {
    id: "5",
    device: "家用 MacBook",
    deviceId: "334 902 115",
    icon: Laptop,
    type: "outgoing",
    date: "2026-03-02",
    start: "20:14",
    end: "22:01",
    duration: "1小时47分",
    status: "completed",
    transferred: "567 MB",
    quality: 90,
  },
  {
    id: "6",
    device: "Linux 服务器",
    deviceId: "567 234 891",
    icon: Server,
    type: "incoming",
    date: "2026-03-01",
    start: "10:00",
    end: "10:30",
    duration: "30分钟",
    status: "completed",
    transferred: "45 MB",
    quality: 97,
  },
];

const totalHours = "47小时12分";
const totalSessions = 47;
const totalTransfer = "28.4 GB";

interface ConnectionsModalProps {
  open: boolean;
  onClose: () => void;
}

export function ConnectionsModal({ open, onClose }: ConnectionsModalProps) {
  const { isDark } = useTheme();
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("全部");
  const [typeFilter, setTypeFilter] = useState("全部");
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (open) {
      requestAnimationFrame(() => setVisible(true));
    } else {
      setVisible(false);
    }
  }, [open]);

  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && open) onClose();
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [open, onClose]);

  if (!open && !visible) return null;

  const filters = ["全部", "今天", "本周", "本月"];
  const types = ["全部", "主动连接", "被动接入"];

  const filtered = sessions.filter((s) => {
    const matchSearch =
      s.device.toLowerCase().includes(search.toLowerCase()) ||
      s.deviceId.includes(search);
    const matchType =
      typeFilter === "全部" ||
      (typeFilter === "主动连接" && s.type === "outgoing") ||
      (typeFilter === "被动接入" && s.type === "incoming");
    return matchSearch && matchType;
  });

  const grouped = filtered.reduce((acc, s) => {
    if (!acc[s.date]) acc[s.date] = [];
    acc[s.date].push(s);
    return acc;
  }, {} as Record<string, typeof sessions>);

  const card = isDark ? "bg-[#2a2a2a] border-gray-700" : "bg-gray-50 border-gray-200";
  const textPrimary = isDark ? "text-gray-100" : "text-gray-900";
  const textSecondary = isDark ? "text-gray-400" : "text-gray-500";
  const textTertiary = isDark ? "text-gray-500" : "text-gray-400";
  const textBody = isDark ? "text-gray-200" : "text-gray-800";
  const inputBg = isDark
    ? "bg-[#2a2a2a] border-gray-600 text-gray-200 placeholder-gray-500 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20"
    : "bg-white border-gray-200 text-gray-900 placeholder-gray-400 focus:border-blue-400 focus:ring-2 focus:ring-blue-100";
  const filterBg = isDark ? "bg-[#2a2a2a] border-gray-700" : "bg-gray-100 border-gray-200";
  const filterActive = isDark ? "bg-blue-900/30 text-blue-400" : "bg-white text-blue-600 shadow-sm";
  const filterInactive = isDark
    ? "text-gray-400 hover:text-gray-200 hover:bg-gray-700"
    : "text-gray-500 hover:text-gray-700 hover:bg-white/60";
  const divider = isDark ? "bg-gray-700" : "bg-gray-200";

  return (
    <div
      className={`fixed inset-0 z-50 flex items-center justify-center p-6 transition-opacity duration-200 ${
        visible && open ? "opacity-100" : "opacity-0 pointer-events-none"
      }`}
    >
      {/* Backdrop */}
      <div
        className={`absolute inset-0 ${isDark ? "bg-black/60" : "bg-black/40"} backdrop-blur-sm`}
        onClick={onClose}
      />

      {/* Panel */}
      <div
        className={`relative rounded-xl border shadow-2xl flex flex-col overflow-hidden transition-transform duration-200 ${
          visible && open ? "scale-100" : "scale-95"
        } ${isDark ? "bg-[#1e1e1e] border-gray-700" : "bg-white border-gray-200"}`}
        style={{ width: 820, maxHeight: "calc(100vh - 80px)" }}
      >
        {/* Modal header */}
        <div
          className={`flex items-center gap-3 px-5 py-3.5 border-b shrink-0 ${
            isDark ? "border-gray-700 bg-[#222]" : "border-gray-200 bg-gray-50"
          }`}
        >
          <div className={`w-7 h-7 rounded-lg flex items-center justify-center ${isDark ? "bg-blue-900/40" : "bg-blue-50"}`}>
            <History className="w-3.5 h-3.5 text-blue-600" />
          </div>
          <div className="flex-1">
            <h2 className={`font-semibold ${textPrimary}`} style={{ fontSize: 14 }}>
              连接记录
            </h2>
            <p className={textTertiary} style={{ fontSize: 11 }}>
              所有历史远程会话记录
            </p>
          </div>
          <button
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border transition-colors ${
              isDark
                ? "border-gray-600 text-gray-400 hover:text-gray-200 hover:bg-gray-800"
                : "border-gray-200 text-gray-600 hover:text-gray-900 hover:bg-gray-100"
            }`}
            style={{ fontSize: 12 }}
          >
            <Download className="w-3 h-3" />
            导出记录
          </button>
          <button
            onClick={onClose}
            className={`flex items-center justify-center w-7 h-7 rounded-lg transition-colors ${
              isDark ? "text-gray-400 hover:bg-gray-700 hover:text-gray-200" : "text-gray-400 hover:bg-gray-200 hover:text-gray-700"
            }`}
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Stats bar */}
        <div className={`flex items-center gap-0 border-b shrink-0 ${isDark ? "border-gray-700" : "border-gray-100"}`}>
          {[
            { label: "本月总时长", value: totalHours, color: "text-blue-600" },
            { label: "连接次数", value: `${totalSessions} 次`, color: "text-green-600" },
            { label: "数据传输", value: totalTransfer, color: "text-purple-600" },
          ].map((s, i) => (
            <div
              key={s.label}
              className={`flex-1 px-5 py-3 ${i < 2 ? (isDark ? "border-r border-gray-700" : "border-r border-gray-100") : ""}`}
            >
              <div className={`font-semibold ${s.color}`} style={{ fontSize: 16 }}>
                {s.value}
              </div>
              <div className={textTertiary} style={{ fontSize: 11 }}>
                {s.label}
              </div>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div className={`flex items-center gap-3 px-5 py-3 border-b shrink-0 ${isDark ? "border-gray-700" : "border-gray-100"}`}>
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-gray-400" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="搜索连接记录..."
              className={`pl-8 pr-3 py-1.5 rounded-lg border outline-none transition-all ${inputBg}`}
              style={{ fontSize: 13, width: 200 }}
            />
          </div>

          <div className={`flex items-center gap-0.5 p-1 rounded-lg border ${filterBg}`}>
            {filters.map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-2.5 py-1 rounded-md transition-colors ${filter === f ? filterActive : filterInactive}`}
                style={{ fontSize: 12 }}
              >
                {f}
              </button>
            ))}
          </div>

          <div className={`flex items-center gap-0.5 p-1 rounded-lg border ${filterBg}`}>
            {types.map((t) => (
              <button
                key={t}
                onClick={() => setTypeFilter(t)}
                className={`px-2.5 py-1 rounded-md transition-colors ${typeFilter === t ? filterActive : filterInactive}`}
                style={{ fontSize: 12 }}
              >
                {t}
              </button>
            ))}
          </div>

          <span className={`ml-auto ${textTertiary}`} style={{ fontSize: 12 }}>
            共 {filtered.length} 条记录
          </span>
        </div>

        {/* Sessions list */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
          {Object.entries(grouped).map(([date, daySessions]) => (
            <div key={date}>
              <div className="flex items-center gap-2.5 mb-2.5">
                <Calendar className={`w-3.5 h-3.5 ${textTertiary}`} />
                <span className={`font-medium ${isDark ? "text-gray-300" : "text-gray-600"}`} style={{ fontSize: 12 }}>
                  {date === "2026-03-04" ? "今天" : date === "2026-03-03" ? "昨天" : date}
                </span>
                <div className={`flex-1 h-px ${divider}`} />
                <span className={textTertiary} style={{ fontSize: 11 }}>
                  {daySessions.length} 次会话
                </span>
              </div>

              <div className="space-y-1.5">
                {daySessions.map((session) => {
                  const Icon = session.icon;
                  return (
                    <div
                      key={session.id}
                      className={`flex items-center gap-3 p-3 rounded-xl border transition-all ${
                        isDark
                          ? "bg-[#232323] border-gray-700 hover:border-gray-600"
                          : "bg-white border-gray-200 hover:border-gray-300 hover:shadow-sm"
                      }`}
                    >
                      {/* Type indicator */}
                      <div
                        className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 ${
                          session.type === "outgoing"
                            ? isDark ? "bg-blue-900/30" : "bg-blue-50"
                            : isDark ? "bg-purple-900/30" : "bg-purple-50"
                        }`}
                      >
                        {session.type === "outgoing" ? (
                          <ArrowUpRight className="w-3.5 h-3.5 text-blue-600" />
                        ) : (
                          <ArrowDownLeft className="w-3.5 h-3.5 text-purple-600" />
                        )}
                      </div>

                      {/* Device icon */}
                      <div className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 ${isDark ? "bg-gray-800" : "bg-gray-100"}`}>
                        <Icon style={{ width: 14, height: 14 }} className={isDark ? "text-gray-400" : "text-gray-500"} />
                      </div>

                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className={`font-medium ${textBody}`} style={{ fontSize: 13 }}>
                            {session.device}
                          </span>
                          <span className={`font-mono ${textTertiary}`} style={{ fontSize: 10 }}>
                            {session.deviceId}
                          </span>
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                          <div className={`flex items-center gap-1 ${textTertiary}`} style={{ fontSize: 11 }}>
                            <Clock className="w-2.5 h-2.5" />
                            {session.start} – {session.end}
                          </div>
                          <span className={isDark ? "text-gray-600" : "text-gray-300"} style={{ fontSize: 11 }}>·</span>
                          <span className={textTertiary} style={{ fontSize: 11 }}>{session.duration}</span>
                        </div>
                      </div>

                      <div className="flex items-center gap-3 text-right shrink-0">
                        {session.status === "completed" ? (
                          <>
                            <div>
                              <div className={isDark ? "text-gray-300" : "text-gray-700"} style={{ fontSize: 12 }}>
                                {session.transferred}
                              </div>
                              <div className={textTertiary} style={{ fontSize: 10 }}>传输量</div>
                            </div>
                            <div>
                              <div className={isDark ? "text-gray-300" : "text-gray-700"} style={{ fontSize: 12 }}>
                                {session.quality}%
                              </div>
                              <div className={textTertiary} style={{ fontSize: 10 }}>画质</div>
                            </div>
                            <div className="flex items-center gap-1 text-green-600" style={{ fontSize: 11 }}>
                              <CheckCircle className="w-3 h-3" />
                              <span>正常</span>
                            </div>
                          </>
                        ) : (
                          <div className="flex items-center gap-1 text-red-500" style={{ fontSize: 11 }}>
                            <XCircle className="w-3 h-3" />
                            <span>失败</span>
                          </div>
                        )}
                        <button
                          className={`p-1 rounded-md transition-colors ${
                            isDark
                              ? "text-gray-600 hover:text-red-400 hover:bg-red-900/20"
                              : "text-gray-300 hover:text-red-500 hover:bg-red-50"
                          }`}
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
