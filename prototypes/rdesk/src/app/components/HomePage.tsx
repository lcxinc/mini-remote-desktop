import { useState } from "react";
import { useNavigate } from "react-router";
import {
  Monitor,
  Copy,
  RefreshCw,
  ArrowRight,
  Clock,
  Star,
  Laptop,
  Smartphone,
  Server,
  ChevronRight,
  Eye,
  EyeOff,
  Zap,
  Globe,
  Users,
} from "lucide-react";
import { useTheme } from "./ThemeContext";

const recentConnections = [
  {
    id: "1",
    name: "办公室电脑",
    deviceId: "821 456 789",
    os: "Windows 11",
    icon: Monitor,
    lastConnected: "刚刚",
    status: "online",
    location: "北京",
    ping: 18,
  },
  {
    id: "2",
    name: "家用 MacBook",
    deviceId: "334 902 115",
    os: "macOS Sonoma",
    icon: Laptop,
    lastConnected: "2小时前",
    status: "online",
    location: "上海",
    ping: 35,
  },
  {
    id: "3",
    name: "Linux 服务器",
    deviceId: "567 234 891",
    os: "Ubuntu 22.04",
    icon: Server,
    lastConnected: "昨天",
    status: "offline",
    location: "深圳",
    ping: null,
  },
  {
    id: "4",
    name: "iPhone 15 Pro",
    deviceId: "198 774 302",
    os: "iOS 17",
    icon: Smartphone,
    lastConnected: "3天前",
    status: "offline",
    location: "广州",
    ping: null,
  },
];

const stats = [
  { label: "本月连接", value: "47", icon: Zap, color: "text-blue-600", bg: "bg-blue-50", bgDark: "bg-blue-900/30" },
  { label: "在线设备", value: "2", icon: Globe, color: "text-green-600", bg: "bg-green-50", bgDark: "bg-green-900/30" },
  { label: "共享会话", value: "5", icon: Users, color: "text-purple-600", bg: "bg-purple-50", bgDark: "bg-purple-900/30" },
];

export function HomePage() {
  const { isDark } = useTheme();
  const navigate = useNavigate();
  const [connectId, setConnectId] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [myId] = useState("456 123 789");
  const [myPassword] = useState("xK9#mZ2");
  const [showMyPassword, setShowMyPassword] = useState(false);
  const [copied, setCopied] = useState(false);
  const [favorites] = useState(["1", "2"]);

  const handleCopy = () => {
    navigator.clipboard.writeText(myId.replace(/\s/g, ""));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleConnect = () => {
    if (!connectId.trim()) return;
    const found = recentConnections.find(
      (d) => d.deviceId.replace(/\s/g, "") === connectId.replace(/\s/g, "")
    );
    if (found) {
      navigate(`/session/${found.id}`);
    } else {
      navigate(`/session/custom?deviceId=${connectId}`);
    }
  };

  // Reusable dark-aware classes
  const card = isDark ? "bg-[#232323] border-gray-700" : "bg-white border-gray-200/70 shadow-sm";
  const textPrimary = isDark ? "text-gray-100" : "text-gray-900";
  const textSecondary = isDark ? "text-gray-400" : "text-gray-500";
  const textTertiary = isDark ? "text-gray-500" : "text-gray-400";
  const textBody = isDark ? "text-gray-300" : "text-gray-700";
  const inputBg = isDark
    ? "bg-[#2a2a2a] border-gray-600 text-gray-200 placeholder-gray-500 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20"
    : "bg-gray-50 border-gray-200 text-gray-900 placeholder-gray-400 focus:border-blue-400 focus:ring-2 focus:ring-blue-100";
  const btnSecondary = isDark
    ? "border-gray-600 text-gray-400 hover:bg-gray-800 hover:text-gray-200"
    : "border-gray-200 text-gray-500 hover:bg-gray-50 hover:text-gray-800";

  return (
    <div className="p-8 max-w-6xl mx-auto">
      <div className="grid grid-cols-5 gap-6">
        {/* Left: ID + Connect */}
        <div className="col-span-2 space-y-5">
          {/* My ID card */}
          <div className={`p-5 rounded-xl border ${card}`}>
            <div className="flex items-center gap-2 mb-4">
              <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
              <span className={textSecondary} style={{ fontSize: 13 }}>本机 ID</span>
            </div>

            <div className="text-center mb-4">
              <div className={`text-3xl font-mono tracking-widest mb-1 ${textPrimary}`}>
                {myId}
              </div>
              <div className={textTertiary} style={{ fontSize: 12 }}>
                当前设备可接受远程连接
              </div>
            </div>

            <div className="flex gap-2 mb-4">
              <button
                onClick={handleCopy}
                className={`flex-1 flex items-center justify-center gap-2 py-2 rounded-lg border transition-all ${
                  copied
                    ? "bg-green-50 border-green-300 text-green-600"
                    : btnSecondary
                }`}
                style={{ fontSize: 13 }}
              >
                <Copy className="w-3.5 h-3.5" />
                {copied ? "已复制" : "复制 ID"}
              </button>
              <button className={`flex items-center justify-center px-3 py-2 rounded-lg border transition-colors ${btnSecondary}`}>
                <RefreshCw className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Password */}
            <div className={`p-3 rounded-lg border ${isDark ? "bg-[#2a2a2a] border-gray-600" : "bg-gray-50 border-gray-100"}`}>
              <div className="flex items-center justify-between">
                <span className={textTertiary} style={{ fontSize: 12 }}>接入密码</span>
                <button
                  onClick={() => setShowMyPassword(!showMyPassword)}
                  className={`transition-colors ${isDark ? "text-gray-500 hover:text-gray-300" : "text-gray-400 hover:text-gray-600"}`}
                >
                  {showMyPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                </button>
              </div>
              <div className={`font-mono mt-1 ${textBody}`} style={{ fontSize: 15 }}>
                {showMyPassword ? myPassword : "••••••••"}
              </div>
            </div>
          </div>

          {/* Connect card */}
          <div className={`p-5 rounded-xl border ${card}`}>
            <h3 className={`mb-4 ${textPrimary}`} style={{ fontSize: 15 }}>连接到远程设备</h3>

            <div className="space-y-3">
              <div>
                <label className={`block mb-1.5 ${textSecondary}`} style={{ fontSize: 12 }}>
                  远程设备 ID
                </label>
                <input
                  type="text"
                  value={connectId}
                  onChange={(e) => setConnectId(e.target.value)}
                  placeholder="例如：821 456 789"
                  onKeyDown={(e) => e.key === "Enter" && handleConnect()}
                  className={`w-full px-3 py-2.5 rounded-lg border outline-none transition-all ${inputBg}`}
                  style={{ fontSize: 14 }}
                />
              </div>

              <div>
                <label className={`block mb-1.5 ${textSecondary}`} style={{ fontSize: 12 }}>
                  密码（可选）
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="输入密码"
                    className={`w-full px-3 py-2.5 pr-9 rounded-lg border outline-none transition-all ${inputBg}`}
                    style={{ fontSize: 14 }}
                  />
                  <button
                    onClick={() => setShowPassword(!showPassword)}
                    className={`absolute right-2.5 top-1/2 -translate-y-1/2 ${isDark ? "text-gray-500 hover:text-gray-300" : "text-gray-400 hover:text-gray-600"}`}
                  >
                    {showPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              <button
                onClick={handleConnect}
                disabled={!connectId.trim()}
                className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed text-white transition-colors shadow-sm"
                style={{ fontSize: 14 }}
              >
                <span>立即连接</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>

        {/* Right: Recent connections */}
        <div className="col-span-3">
          <div className={`p-5 rounded-xl border h-full ${card}`}>
            <div className="flex items-center justify-between mb-4">
              <h3 className={textPrimary} style={{ fontSize: 15 }}>最近连接</h3>
              <button className="flex items-center gap-1 text-blue-600 hover:text-blue-500 transition-colors" style={{ fontSize: 13 }}>
                查看全部 <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="space-y-2">
              {recentConnections.map((device) => {
                const Icon = device.icon;
                const isFav = favorites.includes(device.id);
                return (
                  <div
                    key={device.id}
                    className={`flex items-center gap-3 p-3.5 rounded-lg border border-transparent transition-all group cursor-pointer ${
                      isDark
                        ? "bg-[#2a2a2a]/60 hover:bg-[#333] hover:border-gray-600"
                        : "bg-gray-50/60 hover:bg-gray-100 hover:border-gray-200"
                    }`}
                    onClick={() => device.status === "online" && navigate(`/session/${device.id}`)}
                  >
                    <div className={`relative w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${
                      device.status === "online"
                        ? isDark ? "bg-blue-900/30" : "bg-blue-50"
                        : isDark ? "bg-gray-800" : "bg-gray-100"
                    }`}>
                      <Icon className={`w-4.5 h-4.5 ${device.status === "online" ? "text-blue-600" : "text-gray-400"}`} style={{ width: 18, height: 18 }} />
                      <div className={`absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full border-2 ${
                        isDark ? "border-[#232323]" : "border-white"
                      } ${device.status === "online" ? "bg-green-500" : "bg-gray-300"}`} />
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className={`font-medium truncate ${isDark ? "text-gray-200" : "text-gray-800"}`} style={{ fontSize: 14 }}>
                          {device.name}
                        </span>
                        {isFav && <Star className="w-3 h-3 text-yellow-500 shrink-0 fill-yellow-500" />}
                      </div>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className={`font-mono ${textTertiary}`} style={{ fontSize: 11 }}>{device.deviceId}</span>
                        <span className={isDark ? "text-gray-600" : "text-gray-300"} style={{ fontSize: 11 }}>·</span>
                        <span className={textTertiary} style={{ fontSize: 11 }}>{device.os}</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-3 text-right">
                      {device.ping !== null ? (
                        <div className={`flex items-center gap-1 ${
                          device.ping < 30 ? "text-green-600" : device.ping < 60 ? "text-yellow-600" : "text-red-500"
                        }`} style={{ fontSize: 12 }}>
                          <div className="w-1.5 h-1.5 rounded-full bg-current" />
                          <span>{device.ping}ms</span>
                        </div>
                      ) : (
                        <span className={textTertiary} style={{ fontSize: 12 }}>{device.lastConnected}</span>
                      )}

                      {device.status === "online" ? (
                        <button
                          onClick={(e) => { e.stopPropagation(); navigate(`/session/${device.id}`); }}
                          className={`flex items-center gap-1 px-2.5 py-1 rounded-md transition-colors opacity-0 group-hover:opacity-100 ${
                            isDark ? "bg-blue-900/30 text-blue-400 hover:bg-blue-900/50" : "bg-blue-50 text-blue-600 hover:bg-blue-100"
                          }`}
                          style={{ fontSize: 12 }}
                        >
                          连接
                          <ArrowRight className="w-3 h-3" />
                        </button>
                      ) : (
                        <div className="w-16 opacity-0" />
                      )}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Quick tips */}
            <div className={`mt-4 p-3 rounded-lg border flex items-start gap-3 ${
              isDark ? "bg-blue-900/20 border-blue-800" : "bg-blue-50 border-blue-100"
            }`}>
              <Clock className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
              <div>
                <div className={isDark ? "text-blue-400" : "text-blue-700"} style={{ fontSize: 13 }}>提示</div>
                <div className={`mt-0.5 ${textSecondary}`} style={{ fontSize: 12 }}>
                  点击在线设备可快速发起远程连接会话，离线设备将在上线后发送通知。
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}