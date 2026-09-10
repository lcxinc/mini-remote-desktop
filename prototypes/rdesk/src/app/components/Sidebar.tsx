import { devices } from "./deviceData";
import { useState, useEffect, useRef } from "react";
import { useTheme } from "./ThemeContext";
import { NavLink, useLocation, useNavigate } from "react-router";
import {
  Monitor,
  Laptop,
  History,
  FolderOpen,
  Settings,
  Shield,
  LayoutDashboard,
  Server,
  Smartphone,
  ChevronDown,
  Plus,
  Wifi,
  MoreHorizontal,
  Play,
  FolderOpen as FolderIcon,
  Terminal,
  Pencil,
  Power,
  Trash2,
  Copy,
  Star,
} from "lucide-react";

interface SidebarProps {
  collapsed: boolean;
  onOpenConnections: () => void;
  onOpenSettings: () => void;
}

const navItems = [
  { to: "/", label: "控制中心", icon: LayoutDashboard, end: true },
  { to: "/devices", label: "我的设备", icon: Monitor },
];

const iconMap: Record<string, typeof Monitor> = {
  Monitor,
  Laptop,
  Server,
  Smartphone,
};

export function Sidebar({ collapsed, onOpenConnections, onOpenSettings }: SidebarProps) {
  const [devicesExpanded, setDevicesExpanded] = useState(true);
  const [contextMenu, setContextMenu] = useState<{ deviceId: string; x: number; y: number } | null>(null);
  const contextMenuRef = useRef<HTMLDivElement>(null);
  const location = useLocation();
  const navigate = useNavigate();
  const { isDark } = useTheme();

  const onlineDevices = devices.filter((d) => d.status === "online");
  const offlineDevices = devices.filter((d) => d.status === "offline");

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (contextMenuRef.current && !contextMenuRef.current.contains(e.target as Node)) {
        setContextMenu(null);
      }
    };
    if (contextMenu) {
      document.addEventListener("mousedown", handleClickOutside);
      return () => document.removeEventListener("mousedown", handleClickOutside);
    }
  }, [contextMenu]);

  const handleContextMenu = (e: React.MouseEvent, deviceId: string) => {
    e.preventDefault();
    e.stopPropagation();
    setContextMenu({ deviceId, x: e.clientX, y: e.clientY });
  };

  const handleMoreClick = (e: React.MouseEvent, deviceId: string) => {
    e.stopPropagation();
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
    setContextMenu({ deviceId, x: rect.right, y: rect.bottom });
  };

  const contextMenuDevice = contextMenu ? devices.find((d) => d.id === contextMenu.deviceId) : null;
  const isContextOnline = contextMenuDevice?.status === "online";

  const menuItems = [
    ...(isContextOnline
      ? [
          { icon: Play, label: "远程桌面", action: () => { navigate(`/devices/${contextMenu!.deviceId}`); setContextMenu(null); } },
          { icon: FolderIcon, label: "文件传输", action: () => { navigate(`/devices/${contextMenu!.deviceId}`); setContextMenu(null); } },
          { icon: Terminal, label: "远程终端", action: () => { navigate(`/devices/${contextMenu!.deviceId}`); setContextMenu(null); } },
          { type: "divider" as const },
        ]
      : []),
    { icon: Pencil, label: "重命名", action: () => setContextMenu(null) },
    { icon: Star, label: "收藏设备", action: () => setContextMenu(null) },
    { icon: Copy, label: "复制 ID", action: () => setContextMenu(null) },
    { type: "divider" as const },
    ...(isContextOnline
      ? [{ icon: Power, label: "断开连接", action: () => setContextMenu(null), danger: true }]
      : []),
    { icon: Trash2, label: "移除设备", action: () => setContextMenu(null), danger: true },
  ];

  return (
    <aside
      className={`relative flex flex-col transition-all duration-300 shrink-0 border-r rounded-l-lg ${ 
        isDark ? "bg-[#1e1e1e] border-gray-700" : "bg-[#e9ecf2] border-gray-300/50"
      }`}
      style={{ width: collapsed ? 56 : 220 }}
    >
      {/* App branding */}
      <div className={`flex items-center justify-center gap-2.5 px-4 py-4 shrink-0 border-b ${isDark ? "border-gray-700" : "border-gray-300/30"}`}>
        <div
          className="rounded bg-gradient-to-br from-yellow-400 to-yellow-600 flex items-center justify-center shadow-sm shrink-0 transition-all duration-300"
          style={{ width: collapsed ? 28 : 34, height: collapsed ? 28 : 34 }}
        >
          <Wifi
            className="text-white transition-all duration-300"
            style={{ width: collapsed ? 14 : 18, height: collapsed ? 14 : 18 }}
          />
        </div>
        {!collapsed && (
          <span
            className={`font-semibold tracking-tight ${isDark ? "text-gray-200" : "text-gray-800"}`}
            style={{ fontSize: 15 }}
          >
            R-Desk
          </span>
        )}
      </div>

      {/* Nav */}
      <nav className="py-3 px-2 space-y-0.5 shrink-0">
        {navItems.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              `flex items-center gap-2.5 px-2.5 py-2 rounded-md transition-all duration-150 group relative ${
                isActive
                  ? isDark ? "bg-blue-900/30 text-blue-400" : "bg-white/80 text-blue-600 shadow-sm"
                  : isDark ? "text-gray-400 hover:bg-gray-800 hover:text-gray-200" : "text-gray-600 hover:bg-white/50 hover:text-gray-900"
              }`
            }
          >
            {({ isActive }) => (
              <>
                {isActive && (
                  <div className={`absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-4 rounded-r-full ${isDark ? "bg-blue-400" : "bg-blue-600"}`} />
                )}
                <Icon className="shrink-0" style={{ width: 16, height: 16 }} />
                {!collapsed && (
                  <span style={{ fontSize: 13 }} className="font-medium">{label}</span>
                )}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Device list section */}
      {!collapsed && (
        <div className={`flex-1 overflow-y-auto border-t ${isDark ? "border-gray-700" : "border-gray-300/30"}`}>
          {/* Section header */}
          <div className="flex items-center justify-between px-3 py-2">
            <button
              onClick={() => setDevicesExpanded(!devicesExpanded)}
              className={`flex items-center gap-1.5 transition-colors ${isDark ? "text-gray-400 hover:text-gray-200" : "text-gray-500 hover:text-gray-700"}`}
            >
              <ChevronDown
                className={`transition-transform ${devicesExpanded ? "" : "-rotate-90"}`}
                style={{ width: 12, height: 12 }}
              />
              <span style={{ fontSize: 11 }} className="uppercase tracking-wider font-medium">
                设备列表
              </span>
            </button>
            <div className="flex items-center gap-1">
              <button
                className={`p-0.5 rounded transition-colors ${isDark ? "text-gray-400 hover:bg-gray-700 hover:text-gray-200" : "text-gray-400 hover:bg-gray-100 hover:text-gray-600"}`}
                title="添加设备"
              >
                <Plus style={{ width: 14, height: 14 }} />
              </button>
            </div>
          </div>

          {devicesExpanded && (
            <div className="px-1.5 pb-2 space-y-0.5">
              {/* Online devices */}
              {onlineDevices.map((device) => {
                const isActive = location.pathname === `/devices/${device.id}`;
                const DeviceIcon = device.icon;
                return (
                  <button
                    key={device.id}
                    onClick={() => navigate(`/devices/${device.id}`)}
                    onContextMenu={(e) => handleContextMenu(e, device.id)}
                    draggable
                    onDragStart={(e) => e.dataTransfer.setData("deviceId", device.id)}
                    className={`w-full flex items-center gap-2 px-2 py-1.5 rounded-md transition-all text-left group ${
                      isActive
                        ? isDark ? "bg-blue-900/30 text-blue-400" : "bg-blue-50 text-blue-600"
                        : isDark ? "text-gray-200 hover:bg-gray-800" : "text-gray-700 hover:bg-gray-50"
                    }`}
                  >
                    <div className="relative shrink-0">
                      <DeviceIcon style={{ width: 14, height: 14 }} className={isActive ? (isDark ? "text-blue-400" : "text-blue-600") : (isDark ? "text-gray-300" : "text-gray-500")} />
                      <div className={`absolute -bottom-0.5 -right-0.5 w-2 h-2 rounded-full border-[1.5px] bg-green-500 ${isDark ? "border-[#1e1e1e]" : "border-[#e9ecf2]"}`} />
                    </div>
                    <span className="flex-1 min-w-0 truncate" style={{ fontSize: 12 }}>{device.name}</span>
                    {device.ping !== null && (
                      <span className={`shrink-0 ${device.ping < 30 ? "text-green-600" : "text-yellow-600"}`} style={{ fontSize: 10 }}>
                        {device.ping}ms
                      </span>
                    )}
                    <div
                      className={`shrink-0 p-0.5 rounded opacity-0 group-hover:opacity-100 transition-opacity ${isDark ? "hover:bg-gray-700" : "hover:bg-gray-200"}`}
                      onClick={(e) => handleMoreClick(e, device.id)}
                    >
                      <MoreHorizontal style={{ width: 13, height: 13 }} />
                    </div>
                  </button>
                );
              })}

              {/* Divider */}
              {offlineDevices.length > 0 && onlineDevices.length > 0 && (
                <div className="flex items-center gap-2 px-2 py-1">
                  <div className={`flex-1 h-px ${isDark ? "bg-gray-700" : "bg-gray-100"}`} />
                  <span className="text-gray-400" style={{ fontSize: 9 }}>离线</span>
                  <div className={`flex-1 h-px ${isDark ? "bg-gray-700" : "bg-gray-100"}`} />
                </div>
              )}

              {/* Offline devices */}
              {offlineDevices.map((device) => {
                const isActive = location.pathname === `/devices/${device.id}`;
                const DeviceIcon = device.icon;
                return (
                  <button
                    key={device.id}
                    onClick={() => navigate(`/devices/${device.id}`)}
                    onContextMenu={(e) => handleContextMenu(e, device.id)}
                    className={`w-full flex items-center gap-2 px-2 py-1.5 rounded-md transition-all text-left group ${
                      isActive
                        ? isDark ? "bg-gray-800 text-gray-300" : "bg-gray-100 text-gray-600"
                        : isDark ? "text-gray-400 hover:bg-gray-800 hover:text-gray-300" : "text-gray-500 hover:bg-gray-50 hover:text-gray-600"
                    }`}
                  >
                    <div className="relative shrink-0">
                      <DeviceIcon style={{ width: 14, height: 14 }} className={isDark ? "text-gray-500" : "text-gray-400"} />
                      <div className={`absolute -bottom-0.5 -right-0.5 w-2 h-2 rounded-full border-[1.5px] bg-gray-300 ${isDark ? "border-[#1e1e1e]" : "border-[#e9ecf2]"}`} />
                    </div>
                    <span className="flex-1 min-w-0 truncate" style={{ fontSize: 12 }}>{device.name}</span>
                    <span className="shrink-0 text-gray-400" style={{ fontSize: 10 }}>{device.lastSeen}</span>
                    <div
                      className={`shrink-0 p-0.5 rounded opacity-0 group-hover:opacity-100 transition-opacity ${isDark ? "hover:bg-gray-700" : "hover:bg-gray-200"}`}
                      onClick={(e) => handleMoreClick(e, device.id)}
                    >
                      <MoreHorizontal style={{ width: 13, height: 13 }} />
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Collapsed: just show device dots */}
      {collapsed && (
        <div className={`flex-1 overflow-y-auto border-t py-2 px-1 space-y-1 ${isDark ? "border-gray-700" : "border-gray-100"}`}>
          {devices.map((device) => {
            const isActive = location.pathname === `/devices/${device.id}`;
            const DeviceIcon = device.icon;
            return (
              <button
                key={device.id}
                onClick={() => navigate(`/devices/${device.id}`)}
                className={`w-full flex items-center justify-center p-2 rounded-md transition-all ${
                  isActive ? (isDark ? "bg-blue-900/30" : "bg-blue-50") : (isDark ? "hover:bg-gray-800" : "hover:bg-gray-50")
                }`}
                title={`${device.name} (${device.status === "online" ? "在线" : "离线"})`}
              >
                <div className="relative">
                  <DeviceIcon
                    style={{ width: 15, height: 15 }}
                    className={isActive ? (isDark ? "text-blue-400" : "text-blue-600") : device.status === "online" ? (isDark ? "text-gray-300" : "text-gray-600") : "text-gray-400"}
                  />
                  <div className={`absolute -bottom-0.5 -right-1 w-2 h-2 rounded-full border-[1.5px] ${isDark ? "border-[#1e1e1e]" : "border-[#e9ecf2]"} ${
                    device.status === "online" ? "bg-green-500" : "bg-gray-300"
                  }`} />
                </div>
              </button>
            );
          })}
        </div>
      )}

      {/* Context menu */}
      {contextMenu && (
        <div
          ref={contextMenuRef}
          className={`fixed z-50 min-w-[160px] rounded-lg border py-1 shadow-xl ${
            isDark ? "bg-[#2a2a2a] border-gray-700" : "bg-white border-gray-200"
          }`}
          style={{ left: contextMenu.x, top: contextMenu.y }}
        >
          {menuItems.map((item, index) => {
            if ('type' in item && item.type === "divider") {
              return (
                <div key={index} className={`h-px my-1 mx-2 ${isDark ? "bg-gray-700" : "bg-gray-100"}`} />
              );
            }
            const ItemIcon = 'icon' in item ? item.icon : null;
            const isDanger = 'danger' in item && item.danger;
            return (
              <button
                key={index}
                className={`w-full flex items-center gap-2.5 px-3 py-1.5 text-left transition-colors ${
                  isDanger
                    ? isDark ? "text-red-400 hover:bg-red-900/30" : "text-red-500 hover:bg-red-50"
                    : isDark ? "text-gray-300 hover:bg-gray-700" : "text-gray-600 hover:bg-gray-50"
                }`}
                style={{ fontSize: 12 }}
                onClick={'action' in item ? item.action : undefined}
              >
                {ItemIcon && <ItemIcon style={{ width: 14, height: 14 }} className="shrink-0" />}
                <span>{'label' in item ? item.label : ''}</span>
              </button>
            );
          })}
        </div>
      )}
    </aside>
  );
}