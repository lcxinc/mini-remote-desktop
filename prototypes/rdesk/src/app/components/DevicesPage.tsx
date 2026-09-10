import { useState } from "react";
import { useNavigate } from "react-router";
import {
  Plus,
  Search,
  MoreVertical,
  Star,
  Trash2,
  Edit2,
  ExternalLink,
  Wifi,
  WifiOff,
  MapPin,
  Clock,
  Globe,
  ChevronRight,
  ChevronDown,
  Settings,
  Monitor as MonitorIcon,
} from "lucide-react";
import { devices } from "./deviceData";
import { useTheme } from "./ThemeContext";

const groups = ["全部", "工作", "个人", "服务器"];

const viewTabs = [
  { key: "devices", label: "我的设备" },
  { key: "network", label: "组网设置" },
] as const;

type ViewTab = (typeof viewTabs)[number]["key"];

export function DevicesPage() {
  const { isDark } = useTheme();
  const navigate = useNavigate();
  const [search, setSearch] = useState("");
  const [activeGroup, setActiveGroup] = useState("全部");
  const [selectedDevice, setSelectedDevice] = useState<string | null>(null);
  const [menuOpen, setMenuOpen] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<ViewTab>("devices");
  const [selectedNetwork, setSelectedNetwork] = useState(networks[0].id);
  const [networkDropdownOpen, setNetworkDropdownOpen] = useState(false);
  const [networkSubTab, setNetworkSubTab] = useState<"devices" | "settings">("devices");

  const filtered = devices.filter((d) => {
    const matchSearch =
      d.name.toLowerCase().includes(search.toLowerCase()) ||
      d.deviceId.includes(search) ||
      d.os.toLowerCase().includes(search.toLowerCase());
    const matchGroup = activeGroup === "全部" || d.group === activeGroup;
    return matchSearch && matchGroup;
  });

  const online = devices.filter((d) => d.status === "online").length;

  const card = isDark ? "bg-[#232323] border-gray-700" : "bg-white border-gray-200/70 shadow-sm";
  const cardHover = isDark ? "hover:border-gray-600 hover:shadow-sm" : "hover:border-gray-300 hover:shadow-md";
  const textPrimary = isDark ? "text-gray-100" : "text-gray-900";
  const textSecondary = isDark ? "text-gray-400" : "text-gray-500";
  const textTertiary = isDark ? "text-gray-500" : "text-gray-400";
  const textBody = isDark ? "text-gray-200" : "text-gray-800";
  const inputBg = isDark
    ? "bg-[#2a2a2a] border-gray-600 text-gray-200 placeholder-gray-500"
    : "bg-[#f7f8fa] border-gray-200 text-gray-900 placeholder-gray-400";
  const filterBg = isDark ? "bg-[#232323] border-gray-700" : "bg-white border-gray-200/80";
  const filterActive = isDark ? "bg-blue-900/30 text-blue-400" : "bg-blue-50 text-blue-600";
  const filterInactive = isDark ? "text-gray-400 hover:text-gray-200 hover:bg-gray-800" : "text-gray-500 hover:text-gray-700 hover:bg-gray-50";
  const tabActive = isDark
    ? "bg-[#232323] text-gray-100 shadow-sm border-gray-600"
    : "bg-white text-gray-900 shadow-sm border-gray-200";
  const tabInactive = isDark
    ? "text-gray-400 hover:text-gray-200 border-transparent"
    : "text-gray-500 hover:text-gray-700 border-transparent";

  const currentNetwork = networks.find((n) => n.id === selectedNetwork) || networks[0];
  const networkDevices = devices.filter((d) => currentNetwork.deviceIds.includes(d.id));

  return (
    <div className="flex h-full">
      {/* Main list */}
      <div className="flex-1 p-8 overflow-y-auto">
        {/* Toolbar: view tabs + contextual controls */}
        <div className="flex items-center gap-3 mb-5">
          {/* View switcher tabs */}
          <div className={`inline-flex items-center gap-1 p-1 rounded-xl ${isDark ? "bg-[#2a2a2a]" : "bg-gray-100"}`}>
            {viewTabs.map((tab) => (
              <button
                key={tab.key}
                onClick={() => setActiveView(tab.key)}
                className={`px-4 py-1.5 rounded-lg border transition-all ${
                  activeView === tab.key ? tabActive : tabInactive
                }`}
                style={{ fontSize: 13 }}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Devices view: search + group filters + add button */}
          {activeView === "devices" && (
            <>
              <div className="relative flex-1 max-w-xs">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="搜索设备..."
                  className={`w-full pl-9 pr-3 py-1.5 rounded-lg border outline-none transition-all ${inputBg}`}
                  style={{ fontSize: 13 }}
                />
              </div>
              <div className={`flex items-center gap-1 p-0.5 rounded-lg border ${filterBg}`}>
                {groups.map((g) => (
                  <button
                    key={g}
                    onClick={() => setActiveGroup(g)}
                    className={`px-2.5 py-1 rounded-md transition-colors ${
                      activeGroup === g ? filterActive : filterInactive
                    }`}
                    style={{ fontSize: 12 }}
                  >
                    {g}
                  </button>
                ))}
              </div>
              <div className="flex-1" />
              <button className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors shadow-sm" style={{ fontSize: 13 }}>
                <Plus className="w-3.5 h-3.5" />
                添加设备
              </button>
            </>
          )}

          {/* Network view: network selector + subnet + sub-tabs */}
          {activeView === "network" && (
            <>
              {/* Network selector dropdown */}
              <div className="relative">
                <button
                  onClick={() => setNetworkDropdownOpen(!networkDropdownOpen)}
                  className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border transition-colors ${
                    isDark
                      ? "bg-[#232323] border-gray-600 text-gray-200 hover:border-gray-500"
                      : "bg-white border-gray-200 text-gray-800 hover:border-gray-300"
                  }`}
                  style={{ fontSize: 13 }}
                >
                  <Globe className="w-3.5 h-3.5 text-green-600" />
                  <span className="font-medium">{currentNetwork.name}</span>
                  <ChevronDown className={`w-3.5 h-3.5 transition-transform ${networkDropdownOpen ? "rotate-180" : ""} ${isDark ? "text-gray-400" : "text-gray-500"}`} />
                </button>
                {networkDropdownOpen && (
                  <div className={`absolute left-0 top-full mt-1 w-52 py-1 rounded-lg border shadow-lg z-20 ${
                    isDark ? "bg-[#2a2a2a] border-gray-600" : "bg-white border-gray-200"
                  }`}>
                    {networks.map((net) => (
                      <button
                        key={net.id}
                        onClick={() => { setSelectedNetwork(net.id); setNetworkDropdownOpen(false); }}
                        className={`flex items-center gap-2.5 w-full px-3 py-2 text-left transition-colors ${
                          selectedNetwork === net.id
                            ? isDark ? "bg-blue-900/30 text-blue-400" : "bg-blue-50 text-blue-600"
                            : isDark ? "text-gray-300 hover:bg-gray-700" : "text-gray-600 hover:bg-gray-50"
                        }`}
                        style={{ fontSize: 12 }}
                      >
                        <Globe className={`w-3.5 h-3.5 ${net.status === "active" ? "text-green-600" : "text-gray-400"}`} />
                        <span className="flex-1">{net.name}</span>
                        <span className={`font-mono ${isDark ? "text-gray-500" : "text-gray-400"}`} style={{ fontSize: 10 }}>{net.subnet}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* Current subnet badge */}
              <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md ${
                isDark ? "bg-[#2a2a2a] text-gray-400" : "bg-gray-100 text-gray-500"
              }`} style={{ fontSize: 12 }}>
                <span className="font-mono">{currentNetwork.subnet}</span>
                <span className={isDark ? "text-gray-600" : "text-gray-300"}>·</span>
                <span>{currentNetwork.deviceIds.length} 台设备</span>
              </div>

              {/* Sub-tabs: 设备 / 设置 */}
              <div className={`flex items-center gap-1 p-0.5 rounded-lg border ${filterBg}`}>
                {([
                  { key: "devices" as const, label: "设备", icon: MonitorIcon },
                  { key: "settings" as const, label: "设置", icon: Settings },
                ]).map((tab) => (
                  <button
                    key={tab.key}
                    onClick={() => setNetworkSubTab(tab.key)}
                    className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md transition-colors ${
                      networkSubTab === tab.key ? filterActive : filterInactive
                    }`}
                    style={{ fontSize: 12 }}
                  >
                    <tab.icon className="w-3 h-3" />
                    {tab.label}
                  </button>
                ))}
              </div>

              <div className="flex-1" />
              <button className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors shadow-sm" style={{ fontSize: 13 }}>
                <Plus className="w-3.5 h-3.5" />
                添加到网络
              </button>
            </>
          )}
        </div>

        {/* Content */}
        {activeView === "devices" ? (
        <div className="grid grid-cols-2 gap-3">
          {filtered.map((device) => {
            const Icon = device.icon;
            const isSelected = selectedDevice === device.id;
            return (
              <div
                key={device.id}
                onClick={() => navigate(`/devices/${device.id}`)}
                className={`relative p-4 rounded-xl border cursor-pointer transition-all ${
                  isSelected
                    ? isDark ? "bg-blue-900/20 border-blue-700 shadow-sm" : "bg-blue-50/70 border-blue-300 shadow-sm"
                    : `${card} ${cardHover}`
                }`}
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <div className={`relative w-10 h-10 rounded-xl flex items-center justify-center ${
                      device.status === "online"
                        ? isDark ? "bg-blue-900/30" : "bg-blue-50"
                        : isDark ? "bg-gray-800" : "bg-gray-100"
                    }`}>
                      <Icon style={{ width: 20, height: 20 }} className={device.status === "online" ? "text-blue-600" : "text-gray-400"} />
                      <div className={`absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full border-2 ${
                        isDark ? "border-[#232323]" : "border-white"
                      } ${device.status === "online" ? "bg-green-500" : "bg-gray-300"}`} />
                    </div>
                    <div>
                      <div className="flex items-center gap-1.5">
                        <span className={`font-medium ${textBody}`} style={{ fontSize: 14 }}>{device.name}</span>
                        {device.favorite && <Star className="w-3 h-3 text-yellow-500 fill-yellow-500" />}
                      </div>
                      <span className={textTertiary} style={{ fontSize: 12 }}>{device.os}</span>
                    </div>
                  </div>

                  <div className="relative">
                    <button
                      onClick={(e) => { e.stopPropagation(); setMenuOpen(menuOpen === device.id ? null : device.id); }}
                      className={`p-1 rounded-md ${isDark ? "text-gray-500 hover:text-gray-300 hover:bg-gray-700" : "text-gray-400 hover:text-gray-600 hover:bg-gray-100"}`}
                    >
                      <MoreVertical className="w-4 h-4" />
                    </button>
                    {menuOpen === device.id && (
                      <div className={`absolute right-0 top-7 w-36 py-1 rounded-lg border shadow-lg z-10 ${isDark ? "bg-[#2a2a2a] border-gray-600" : "bg-white border-gray-200"}`}>
                        {[
                          { icon: Edit2, label: "重命名" },
                          { icon: Star, label: "收藏" },
                          { icon: Trash2, label: "删除", danger: true },
                        ].map(({ icon: I, label, danger }) => (
                          <button
                            key={label}
                            onClick={(e) => { e.stopPropagation(); setMenuOpen(null); }}
                            className={`flex items-center gap-2 w-full px-3 py-2 text-left transition-colors ${
                              danger
                                ? "text-red-500"
                                : isDark ? "text-gray-300 hover:bg-gray-700" : "text-gray-600 hover:bg-gray-50"
                            }`}
                            style={{ fontSize: 13 }}
                          >
                            <I className="w-3.5 h-3.5" />
                            {label}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-3 mb-3">
                  <div className={`flex items-center gap-1 ${textTertiary}`} style={{ fontSize: 11 }}>
                    <MapPin className="w-3 h-3" />
                    {device.location}
                  </div>
                  <span className={isDark ? "text-gray-600" : "text-gray-300"} style={{ fontSize: 11 }}>·</span>
                  <div className={`flex items-center gap-1 ${textTertiary}`} style={{ fontSize: 11 }}>
                    <Clock className="w-3 h-3" />
                    {device.lastSeen}
                  </div>
                  {device.ping !== null && (
                    <>
                      <span className={isDark ? "text-gray-600" : "text-gray-300"} style={{ fontSize: 11 }}>·</span>
                      <div className={`flex items-center gap-1 ${device.ping < 30 ? "text-green-600" : "text-yellow-600"}`} style={{ fontSize: 11 }}>
                        <Wifi className="w-3 h-3" />
                        {device.ping}ms
                      </div>
                    </>
                  )}
                </div>

                {/* Resource bars */}
                {device.status === "online" && device.cpu !== null && (
                  <div className="space-y-1.5 mb-3">
                    {[
                      { label: "CPU", value: device.cpu, color: "bg-blue-500" },
                      { label: "内存", value: device.ram!, color: "bg-purple-500" },
                      { label: "磁盘", value: device.disk!, color: "bg-green-500" },
                    ].map(({ label, value, color }) => (
                      <div key={label} className="flex items-center gap-2">
                        <span className={`w-6 shrink-0 ${textTertiary}`} style={{ fontSize: 10 }}>{label}</span>
                        <div className={`flex-1 h-1 rounded-full ${isDark ? "bg-gray-700" : "bg-gray-200"}`}>
                          <div
                            className={`h-full rounded-full ${color}`}
                            style={{ width: `${value}%`, opacity: 0.75 }}
                          />
                        </div>
                        <span className={`${textTertiary} w-7 text-right shrink-0`} style={{ fontSize: 10 }}>{value}%</span>
                      </div>
                    ))}
                  </div>
                )}

                {device.status === "online" ? (
                  <button
                    onClick={(e) => { e.stopPropagation(); navigate(`/devices/${device.id}`); }}
                    className={`w-full py-2 rounded-lg transition-colors flex items-center justify-center gap-1.5 ${
                      isDark ? "bg-blue-900/30 hover:bg-blue-900/50 text-blue-400" : "bg-blue-50 hover:bg-blue-100 text-blue-600"
                    }`}
                    style={{ fontSize: 13 }}
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                    查看详情
                  </button>
                ) : (
                  <div className={`w-full py-2 rounded-lg text-center flex items-center justify-center gap-1.5 ${
                    isDark ? "bg-gray-800 text-gray-500" : "bg-gray-50 text-gray-400"
                  }`} style={{ fontSize: 13 }}>
                    <WifiOff className="w-3.5 h-3.5" />
                    设备离线
                  </div>
                )}
              </div>
            );
          })}
        </div>
        ) : (
          <NetworkView
            isDark={isDark}
            network={currentNetwork}
            networkDevices={networkDevices}
            subTab={networkSubTab}
            navigate={navigate}
          />
        )}
      </div>
    </div>
  );
}

/* ── 组网视图 ─────────────────────────────── */
function NetworkView({
  isDark,
  network,
  networkDevices,
  subTab,
  navigate,
}: {
  isDark: boolean;
  network: typeof networks[number];
  networkDevices: typeof devices;
  subTab: "devices" | "settings";
  navigate: ReturnType<typeof useNavigate>;
}) {
  const card = isDark ? "bg-[#232323] border-gray-700" : "bg-white border-gray-200/70 shadow-sm";
  const cardHover = isDark ? "hover:border-gray-600 hover:shadow-sm" : "hover:border-gray-300 hover:shadow-md";
  const textPrimary = isDark ? "text-gray-100" : "text-gray-900";
  const textSecondary = isDark ? "text-gray-400" : "text-gray-500";
  const textTertiary = isDark ? "text-gray-500" : "text-gray-400";
  const textBody = isDark ? "text-gray-200" : "text-gray-800";
  const inputBg = isDark
    ? "bg-[#2a2a2a] border-gray-600 text-gray-200 placeholder-gray-500"
    : "bg-[#f7f8fa] border-gray-200 text-gray-900 placeholder-gray-400";

  if (subTab === "devices") {
    return (
      <div className="grid grid-cols-2 gap-3">
        {networkDevices.map((device) => {
          const Icon = device.icon;
          return (
            <div
              key={device.id}
              onClick={() => navigate(`/devices/${device.id}`)}
              className={`relative p-4 rounded-xl border cursor-pointer transition-all ${card} ${cardHover}`}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-3">
                  <div className={`relative w-10 h-10 rounded-xl flex items-center justify-center ${
                    device.status === "online"
                      ? isDark ? "bg-blue-900/30" : "bg-blue-50"
                      : isDark ? "bg-gray-800" : "bg-gray-100"
                  }`}>
                    <Icon style={{ width: 20, height: 20 }} className={device.status === "online" ? "text-blue-600" : "text-gray-400"} />
                    <div className={`absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full border-2 ${
                      isDark ? "border-[#232323]" : "border-white"
                    } ${device.status === "online" ? "bg-green-500" : "bg-gray-300"}`} />
                  </div>
                  <div>
                    <div className="flex items-center gap-1.5">
                      <span className={`font-medium ${textBody}`} style={{ fontSize: 14 }}>{device.name}</span>
                      {device.favorite && <Star className="w-3 h-3 text-yellow-500 fill-yellow-500" />}
                    </div>
                    <span className={textTertiary} style={{ fontSize: 12 }}>{device.os}</span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-3 mb-3">
                <div className={`flex items-center gap-1 ${textTertiary}`} style={{ fontSize: 11 }}>
                  <Globe className="w-3 h-3" />
                  <span className="font-mono">{device.ip}</span>
                </div>
                <span className={isDark ? "text-gray-600" : "text-gray-300"} style={{ fontSize: 11 }}>·</span>
                <div className={`flex items-center gap-1 ${textTertiary}`} style={{ fontSize: 11 }}>
                  <MapPin className="w-3 h-3" />
                  {device.location}
                </div>
                {device.ping !== null && (
                  <>
                    <span className={isDark ? "text-gray-600" : "text-gray-300"} style={{ fontSize: 11 }}>·</span>
                    <div className={`flex items-center gap-1 ${device.ping < 30 ? "text-green-600" : "text-yellow-600"}`} style={{ fontSize: 11 }}>
                      <Wifi className="w-3 h-3" />
                      {device.ping}ms
                    </div>
                  </>
                )}
              </div>

              {/* Resource bars */}
              {device.status === "online" && device.cpu !== null && (
                <div className="space-y-1.5 mb-3">
                  {[
                    { label: "CPU", value: device.cpu, color: "bg-blue-500" },
                    { label: "内存", value: device.ram!, color: "bg-purple-500" },
                    { label: "磁盘", value: device.disk!, color: "bg-green-500" },
                  ].map(({ label, value, color }) => (
                    <div key={label} className="flex items-center gap-2">
                      <span className={`w-6 shrink-0 ${textTertiary}`} style={{ fontSize: 10 }}>{label}</span>
                      <div className={`flex-1 h-1 rounded-full ${isDark ? "bg-gray-700" : "bg-gray-200"}`}>
                        <div className={`h-full rounded-full ${color}`} style={{ width: `${value}%`, opacity: 0.75 }} />
                      </div>
                      <span className={`${textTertiary} w-7 text-right shrink-0`} style={{ fontSize: 10 }}>{value}%</span>
                    </div>
                  ))}
                </div>
              )}

              <div className={`flex items-center justify-between pt-2 border-t ${isDark ? "border-gray-700" : "border-gray-100"}`}>
                <span className={`font-mono ${textTertiary}`} style={{ fontSize: 11 }}>
                  {device.status === "online" ? "已连接" : "离线"}
                </span>
                {device.status === "online" ? (
                  <button
                    onClick={(e) => { e.stopPropagation(); navigate(`/devices/${device.id}`); }}
                    className={`flex items-center gap-1 px-2.5 py-1 rounded-md transition-colors ${
                      isDark ? "bg-blue-900/30 text-blue-400 hover:bg-blue-900/50" : "bg-blue-50 text-blue-600 hover:bg-blue-100"
                    }`}
                    style={{ fontSize: 12 }}
                  >
                    <ExternalLink className="w-3 h-3" />
                    详情
                  </button>
                ) : (
                  <span className={`flex items-center gap-1 ${textTertiary}`} style={{ fontSize: 12 }}>
                    <WifiOff className="w-3 h-3" />
                    离线
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    );
  }

  // Settings sub-tab
  return (
    <div className="grid grid-cols-2 gap-5">
      <div className={`p-5 rounded-xl border ${card}`}>
        <h4 className={`mb-3 ${textPrimary}`} style={{ fontSize: 14 }}>网络协议</h4>
        <div className="space-y-3">
          {[
            { label: "WireGuard", desc: "高性能加密隧道", enabled: true },
            { label: "QUIC", desc: "低延迟传输协议", enabled: true },
            { label: "TCP 中继", desc: "NAT 穿透失败时回退", enabled: false },
          ].map((proto) => (
            <div key={proto.label} className="flex items-center justify-between">
              <div>
                <div className={textPrimary} style={{ fontSize: 13 }}>{proto.label}</div>
                <div className={textTertiary} style={{ fontSize: 11 }}>{proto.desc}</div>
              </div>
              <div
                className={`w-9 h-5 rounded-full relative cursor-pointer transition-colors ${
                  proto.enabled ? "bg-blue-600" : isDark ? "bg-gray-700" : "bg-gray-200"
                }`}
              >
                <div className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow-sm transition-transform ${
                  proto.enabled ? "left-[18px]" : "left-0.5"
                }`} />
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className={`p-5 rounded-xl border ${card}`}>
        <h4 className={`mb-3 ${textPrimary}`} style={{ fontSize: 14 }}>DNS 设置</h4>
        <div className="space-y-3">
          <div>
            <label className={`block mb-1 ${textSecondary}`} style={{ fontSize: 12 }}>主 DNS</label>
            <input
              defaultValue="10.0.1.1"
              className={`w-full px-3 py-2 rounded-lg border outline-none ${inputBg}`}
              style={{ fontSize: 13 }}
            />
          </div>
          <div>
            <label className={`block mb-1 ${textSecondary}`} style={{ fontSize: 12 }}>备用 DNS</label>
            <input
              defaultValue="8.8.8.8"
              className={`w-full px-3 py-2 rounded-lg border outline-none ${inputBg}`}
              style={{ fontSize: 13 }}
            />
          </div>
          <div>
            <label className={`block mb-1 ${textSecondary}`} style={{ fontSize: 12 }}>自定义域名</label>
            <input
              defaultValue="*.rdesk.local"
              className={`w-full px-3 py-2 rounded-lg border outline-none ${inputBg}`}
              style={{ fontSize: 13 }}
            />
          </div>
        </div>
      </div>

      <div className={`p-5 rounded-xl border ${card}`}>
        <h4 className={`mb-3 ${textPrimary}`} style={{ fontSize: 14 }}>NAT 穿透</h4>
        <div className="space-y-3">
          {[
            { label: "STUN 服务器", value: "stun.rdesk.io:3478" },
            { label: "TURN 服务器", value: "turn.rdesk.io:5349" },
          ].map((item) => (
            <div key={item.label}>
              <label className={`block mb-1 ${textSecondary}`} style={{ fontSize: 12 }}>{item.label}</label>
              <input
                defaultValue={item.value}
                className={`w-full px-3 py-2 rounded-lg border outline-none ${inputBg}`}
                style={{ fontSize: 13 }}
              />
            </div>
          ))}
        </div>
      </div>

      <div className={`p-5 rounded-xl border ${card}`}>
        <h4 className={`mb-3 ${textPrimary}`} style={{ fontSize: 14 }}>安全策略</h4>
        <div className="space-y-3">
          {[
            { label: "端到端加密", desc: "AES-256-GCM", enabled: true },
            { label: "设备认证", desc: "双向 mTLS 验证", enabled: true },
            { label: "流量审计", desc: "记录连接日志", enabled: false },
          ].map((item) => (
            <div key={item.label} className="flex items-center justify-between">
              <div>
                <div className={textPrimary} style={{ fontSize: 13 }}>{item.label}</div>
                <div className={textTertiary} style={{ fontSize: 11 }}>{item.desc}</div>
              </div>
              <div
                className={`w-9 h-5 rounded-full relative cursor-pointer transition-colors ${
                  item.enabled ? "bg-blue-600" : isDark ? "bg-gray-700" : "bg-gray-200"
                }`}
              >
                <div className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow-sm transition-transform ${
                  item.enabled ? "left-[18px]" : "left-0.5"
                }`} />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ── 网络数据 ─────────────────────────────── */
const networks = [
  { id: "net-1", name: "办公网络", subnet: "10.0.1.0/24", deviceIds: ["1", "2", "4"], status: "active" as const },
  { id: "net-2", name: "家庭网络", subnet: "192.168.1.0/24", deviceIds: ["2", "5"], status: "active" as const },
  { id: "net-3", name: "测试环境", subnet: "172.16.0.0/24", deviceIds: ["3", "4"], status: "inactive" as const },
];