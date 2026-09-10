import { useState } from "react";
import {
  Monitor,
  Laptop,
  Server,
  Search,
  Calendar,
  Clock,
  Download,
  Trash2,
  ChevronDown,
  ArrowUpRight,
  ArrowDownLeft,
  Filter,
  CheckCircle,
  XCircle,
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

export function ConnectionsPage() {
  const { isDark } = useTheme();
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("全部");
  const [typeFilter, setTypeFilter] = useState("全部");

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

  const card = isDark ? "bg-[#232323] border-gray-700" : "bg-white border-gray-200 shadow-xs";
  const textPrimary = isDark ? "text-gray-100" : "text-gray-900";
  const textSecondary = isDark ? "text-gray-400" : "text-gray-500";
  const textTertiary = isDark ? "text-gray-500" : "text-gray-400";
  const textBody = isDark ? "text-gray-200" : "text-gray-800";
  const inputBg = isDark
    ? "bg-[#2a2a2a] border-gray-600 text-gray-200 placeholder-gray-500 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20"
    : "bg-white border-gray-200 text-gray-900 placeholder-gray-400 focus:border-blue-400 focus:ring-2 focus:ring-blue-100";
  const filterBg = isDark ? "bg-[#232323] border-gray-700" : "bg-white border-gray-200";
  const filterActive = isDark ? "bg-blue-900/30 text-blue-400" : "bg-blue-50 text-blue-600";
  const filterInactive = isDark ? "text-gray-400 hover:text-gray-200 hover:bg-gray-800" : "text-gray-500 hover:text-gray-700 hover:bg-gray-50";
  const divider = isDark ? "bg-gray-700" : "bg-gray-200";

  return (
    <div className="p-8 max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className={textPrimary} style={{ fontSize: 22 }}>连接记录</h1>
          <p className={`mt-1 ${textSecondary}`} style={{ fontSize: 14 }}>
            所有历史远程会话记录
          </p>
        </div>
        <button className={`flex items-center gap-2 px-3.5 py-2 rounded-lg border transition-colors ${
          isDark ? "border-gray-600 text-gray-400 hover:text-gray-200 hover:bg-gray-800" : "border-gray-200 text-gray-600 hover:text-gray-900 hover:bg-gray-50"
        }`} style={{ fontSize: 13 }}>
          <Download className="w-3.5 h-3.5" />
          导出记录
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        {[
          { label: "本月总时长", value: totalHours, color: "text-blue-600" },
          { label: "连接次数", value: `${totalSessions} 次`, color: "text-green-600" },
          { label: "数据传输", value: totalTransfer, color: "text-purple-600" },
        ].map((s) => (
          <div key={s.label} className={`p-4 rounded-xl border ${card}`}>
            <div className={`font-semibold ${s.color}`} style={{ fontSize: 20 }}>{s.value}</div>
            <div className={`mt-0.5 ${textSecondary}`} style={{ fontSize: 12 }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 mb-6">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="搜索连接记录..."
            className={`w-full pl-9 pr-3 py-2 rounded-lg border outline-none transition-all ${inputBg}`}
            style={{ fontSize: 14 }}
          />
        </div>

        <div className={`flex items-center gap-1 p-1 rounded-lg border ${filterBg}`}>
          {filters.map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1.5 rounded-md transition-colors ${
                filter === f ? filterActive : filterInactive
              }`}
              style={{ fontSize: 13 }}
            >
              {f}
            </button>
          ))}
        </div>

        <div className={`flex items-center gap-1 p-1 rounded-lg border ${filterBg}`}>
          {types.map((t) => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={`px-3 py-1.5 rounded-md transition-colors ${
                typeFilter === t ? filterActive : filterInactive
              }`}
              style={{ fontSize: 13 }}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      {/* Sessions grouped by date */}
      <div className="space-y-6">
        {Object.entries(grouped).map(([date, daySessions]) => (
          <div key={date}>
            <div className="flex items-center gap-3 mb-3">
              <Calendar className={`w-4 h-4 ${textTertiary}`} />
              <span className={`font-medium ${isDark ? "text-gray-300" : "text-gray-600"}`} style={{ fontSize: 13 }}>
                {date === "2026-03-04" ? "今天" : date === "2026-03-03" ? "昨天" : date}
              </span>
              <div className={`flex-1 h-px ${divider}`} />
              <span className={textTertiary} style={{ fontSize: 12 }}>{daySessions.length} 次会话</span>
            </div>

            <div className="space-y-2">
              {daySessions.map((session) => {
                const Icon = session.icon;
                return (
                  <div
                    key={session.id}
                    className={`flex items-center gap-4 p-4 rounded-xl border transition-all ${
                      isDark ? "bg-[#232323] border-gray-700 hover:border-gray-600" : "bg-white border-gray-200 hover:border-gray-300 hover:shadow-xs"
                    }`}
                  >
                    {/* Type indicator */}
                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
                      session.type === "outgoing"
                        ? isDark ? "bg-blue-900/30" : "bg-blue-50"
                        : isDark ? "bg-purple-900/30" : "bg-purple-50"
                    }`}>
                      {session.type === "outgoing" ? (
                        <ArrowUpRight className="w-4 h-4 text-blue-600" />
                      ) : (
                        <ArrowDownLeft className="w-4 h-4 text-purple-600" />
                      )}
                    </div>

                    {/* Device */}
                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${isDark ? "bg-gray-800" : "bg-gray-100"}`}>
                      <Icon style={{ width: 16, height: 16 }} className={isDark ? "text-gray-400" : "text-gray-500"} />
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className={`font-medium ${textBody}`} style={{ fontSize: 14 }}>{session.device}</span>
                        <span className={`font-mono ${textTertiary}`} style={{ fontSize: 11 }}>{session.deviceId}</span>
                      </div>
                      <div className="flex items-center gap-3 mt-0.5">
                        <div className={`flex items-center gap-1 ${textTertiary}`} style={{ fontSize: 12 }}>
                          <Clock className="w-3 h-3" />
                          {session.start} – {session.end}
                        </div>
                        <span className={isDark ? "text-gray-600" : "text-gray-300"} style={{ fontSize: 12 }}>·</span>
                        <span className={textTertiary} style={{ fontSize: 12 }}>{session.duration}</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-4 text-right shrink-0">
                      {session.status === "completed" ? (
                        <>
                          <div className="hidden sm:block">
                            <div className={isDark ? "text-gray-300" : "text-gray-700"} style={{ fontSize: 13 }}>{session.transferred}</div>
                            <div className={textTertiary} style={{ fontSize: 11 }}>传输量</div>
                          </div>
                          <div>
                            <div className={isDark ? "text-gray-300" : "text-gray-700"} style={{ fontSize: 13 }}>{session.quality}%</div>
                            <div className={textTertiary} style={{ fontSize: 11 }}>画质</div>
                          </div>
                          <div className="flex items-center gap-1 text-green-600" style={{ fontSize: 12 }}>
                            <CheckCircle className="w-3.5 h-3.5" />
                            <span>正常</span>
                          </div>
                        </>
                      ) : (
                        <div className="flex items-center gap-1 text-red-500" style={{ fontSize: 12 }}>
                          <XCircle className="w-3.5 h-3.5" />
                          <span>失败</span>
                        </div>
                      )}
                      <button className={`p-1.5 rounded-md transition-colors ${isDark ? "text-gray-500 hover:text-red-400 hover:bg-red-900/20" : "text-gray-400 hover:text-red-500 hover:bg-red-50"}`}>
                        <Trash2 className="w-3.5 h-3.5" />
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
  );
}
