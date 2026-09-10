import { useState, useEffect } from "react";
import {
  Shield,
  Monitor,
  Bell,
  Wifi,
  User,
  Volume2,
  Palette,
  LogOut,
  Trash2,
  X,
  Settings,
} from "lucide-react";
import { useTheme } from "./ThemeContext";

function Toggle({ value, onChange }: { value: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      onClick={() => onChange(!value)}
      className={`relative rounded-full transition-colors ${value ? "bg-blue-600" : "bg-gray-300"}`}
      style={{ height: 22, width: 40 }}
    >
      <div
        className="absolute rounded-full bg-white transition-all shadow-sm"
        style={{ width: 18, height: 18, top: 2, left: value ? 20 : 2 }}
      />
    </button>
  );
}

function ModalSelect({
  value,
  options,
  onChange,
}: {
  value: string;
  options: string[];
  onChange: (v: string) => void;
}) {
  const { isDark } = useTheme();
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className={`border rounded-lg px-3 py-1.5 outline-none cursor-pointer ${
        isDark
          ? "bg-[#2a2a2a] border-gray-600 text-gray-200 focus:border-blue-500"
          : "bg-white border-gray-200 text-gray-700 focus:border-blue-400"
      }`}
      style={{ fontSize: 13 }}
    >
      {options.map((o) => (
        <option key={o} value={o}>
          {o}
        </option>
      ))}
    </select>
  );
}

const sections = [
  { id: "general", label: "通用", icon: Monitor },
  { id: "security", label: "安全", icon: Shield },
  { id: "network", label: "网络", icon: Wifi },
  { id: "display", label: "显示", icon: Palette },
  { id: "audio", label: "音频与输入", icon: Volume2 },
  { id: "notifications", label: "通知", icon: Bell },
  { id: "account", label: "账户", icon: User },
];

interface SettingsModalProps {
  open: boolean;
  onClose: () => void;
}

export function SettingsModal({ open, onClose }: SettingsModalProps) {
  const [active, setActive] = useState("general");
  const { theme: globalTheme, setTheme: setGlobalTheme, isDark } = useTheme();
  const [visible, setVisible] = useState(false);

  const themeMap: Record<string, string> = { light: "浅色", dark: "深色", system: "跟随系统" };
  const reverseThemeMap: Record<string, "light" | "dark" | "system"> = {
    浅色: "light",
    深色: "dark",
    跟随系统: "system",
  };
  const themeLabel = themeMap[globalTheme] || "浅色";

  // General
  const [autoStart, setAutoStart] = useState(true);
  const [minimizeToTray, setMinimizeToTray] = useState(true);
  const [language, setLanguage] = useState("简体中文");

  // Security
  const [twoFA, setTwoFA] = useState(false);
  const [requirePassword, setRequirePassword] = useState(true);
  const [lockOnIdle, setLockOnIdle] = useState(true);
  const [idleTimeout, setIdleTimeout] = useState("5 分钟");
  const [encryptionLevel, setEncryptionLevel] = useState("TLS 1.3");

  // Network
  const [proxy, setProxy] = useState(false);
  const [bandwidth, setBandwidth] = useState("自动");
  const [directConn, setDirectConn] = useState(true);

  // Display
  const [resolution, setResolution] = useState("自适应");
  const [quality, setQuality] = useState("高质量");
  const [colorDepth, setColorDepth] = useState("32位");
  const [showCursor, setShowCursor] = useState(true);

  // Audio
  const [audioOutput, setAudioOutput] = useState(true);
  const [audioInput, setAudioInput] = useState(false);

  // Notifications
  const [notifyConnect, setNotifyConnect] = useState(true);
  const [notifyDisconnect, setNotifyDisconnect] = useState(true);
  const [notifyRequest, setNotifyRequest] = useState(true);
  const [sound, setSound] = useState(true);

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

  const textPrimary = isDark ? "text-gray-100" : "text-gray-900";
  const textSecondary = isDark ? "text-gray-400" : "text-gray-500";
  const textTertiary = isDark ? "text-gray-500" : "text-gray-400";

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
        style={{ width: 880, height: 580 }}
      >
        {/* Modal header */}
        <div
          className={`flex items-center gap-3 px-5 py-3.5 border-b shrink-0 ${
            isDark ? "border-gray-700 bg-[#222]" : "border-gray-200 bg-gray-50"
          }`}
        >
          <div className={`w-7 h-7 rounded-lg flex items-center justify-center ${isDark ? "bg-gray-800" : "bg-gray-100"}`}>
            <Settings className="w-3.5 h-3.5 text-gray-500" />
          </div>
          <h2 className={`flex-1 font-semibold ${textPrimary}`} style={{ fontSize: 14 }}>
            设置
          </h2>
          <button
            onClick={onClose}
            className={`flex items-center justify-center w-7 h-7 rounded-lg transition-colors ${
              isDark ? "text-gray-400 hover:bg-gray-700 hover:text-gray-200" : "text-gray-400 hover:bg-gray-200 hover:text-gray-700"
            }`}
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex flex-1 overflow-hidden">
          {/* Left nav */}
          <div className={`w-44 shrink-0 p-3 border-r ${isDark ? "border-gray-700" : "border-gray-100"}`}>
            <nav className="space-y-0.5">
              {sections.map(({ id, label, icon: Icon }) => (
                <button
                  key={id}
                  onClick={() => setActive(id)}
                  className={`flex items-center gap-2.5 w-full px-3 py-2.5 rounded-lg text-left transition-colors ${
                    active === id
                      ? isDark
                        ? "bg-blue-900/30 text-blue-400"
                        : "bg-blue-50 text-blue-600"
                      : isDark
                      ? "text-gray-400 hover:bg-gray-800 hover:text-gray-200"
                      : "text-gray-500 hover:bg-gray-50 hover:text-gray-800"
                  }`}
                  style={{ fontSize: 13 }}
                >
                  <Icon style={{ width: 15, height: 15 }} className="shrink-0" />
                  {label}
                </button>
              ))}
            </nav>
          </div>

          {/* Right content */}
          <div className="flex-1 p-6 overflow-y-auto">
            {active === "general" && (
              <SettingsSection title="通用设置">
                <SettingRow label="开机自动启动" description="系统启动时自动运行 RemoteDesk">
                  <Toggle value={autoStart} onChange={setAutoStart} />
                </SettingRow>
                <SettingRow label="最小化到托盘" description="关闭窗口时最小化而非退出">
                  <Toggle value={minimizeToTray} onChange={setMinimizeToTray} />
                </SettingRow>
                <SettingRow label="界面语言" description="更改应用显示语言">
                  <ModalSelect value={language} options={["简体中文", "English", "日本語", "한국어"]} onChange={setLanguage} />
                </SettingRow>
                <SettingRow label="界面主题" description="选择应用颜色主题">
                  <ModalSelect
                    value={themeLabel}
                    options={["浅色", "深色", "跟随系统"]}
                    onChange={(v) => setGlobalTheme(reverseThemeMap[v] || "light")}
                  />
                </SettingRow>
              </SettingsSection>
            )}

            {active === "security" && (
              <SettingsSection title="安全设置">
                <SettingRow label="双因素认证" description="为账户启用额外的安全验证">
                  <Toggle value={twoFA} onChange={setTwoFA} />
                </SettingRow>
                <SettingRow label="连接密码" description="接受连接时需要输入密码">
                  <Toggle value={requirePassword} onChange={setRequirePassword} />
                </SettingRow>
                <SettingRow label="空闲自动锁定" description="设备空闲后自动断开连接">
                  <Toggle value={lockOnIdle} onChange={setLockOnIdle} />
                </SettingRow>
                {lockOnIdle && (
                  <SettingRow label="空闲超时" description="超出设定时间后锁定">
                    <ModalSelect
                      value={idleTimeout}
                      options={["1 分钟", "5 分钟", "10 分钟", "30 分钟"]}
                      onChange={setIdleTimeout}
                    />
                  </SettingRow>
                )}
                <SettingRow label="加密协议" description="数据传输加密方式">
                  <ModalSelect
                    value={encryptionLevel}
                    options={["TLS 1.3", "TLS 1.2", "AES-256"]}
                    onChange={setEncryptionLevel}
                  />
                </SettingRow>
                <div
                  className={`p-3.5 rounded-xl border mt-2 ${
                    isDark ? "bg-green-900/20 border-green-800" : "bg-green-50 border-green-200"
                  }`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <Shield className="w-3.5 h-3.5 text-green-600" />
                    <span className={`font-medium ${isDark ? "text-green-400" : "text-green-700"}`} style={{ fontSize: 13 }}>
                      安全状态良好
                    </span>
                  </div>
                  <p className={isDark ? "text-gray-400" : "text-gray-500"} style={{ fontSize: 11 }}>
                    当前使用 TLS 1.3 端对端加密，所有传输数据均受到保护。
                  </p>
                </div>
              </SettingsSection>
            )}

            {active === "network" && (
              <SettingsSection title="网络设置">
                <SettingRow label="使用代理" description="通过代理服务器建立连接">
                  <Toggle value={proxy} onChange={setProxy} />
                </SettingRow>
                <SettingRow label="优先直连" description="尽可能使用直接 P2P 连接">
                  <Toggle value={directConn} onChange={setDirectConn} />
                </SettingRow>
                <SettingRow label="带宽限制" description="限制远程连接使用的网络带宽">
                  <ModalSelect
                    value={bandwidth}
                    options={["自动", "1 Mbps", "5 Mbps", "10 Mbps", "不限制"]}
                    onChange={setBandwidth}
                  />
                </SettingRow>
                <div className={`p-3.5 rounded-xl border mt-2 ${isDark ? "bg-[#2a2a2a] border-gray-700" : "bg-gray-50 border-gray-200"}`}>
                  <div className={`mb-3 ${isDark ? "text-gray-300" : "text-gray-600"}`} style={{ fontSize: 13 }}>
                    网络检测
                  </div>
                  <div className="grid grid-cols-3 gap-4">
                    {[
                      { label: "延迟", value: "24ms", good: true },
                      { label: "下载速度", value: "94 Mbps", good: true },
                      { label: "上传速度", value: "47 Mbps", good: true },
                    ].map((n) => (
                      <div key={n.label} className="text-center">
                        <div className={`font-semibold ${n.good ? "text-green-600" : "text-red-500"}`} style={{ fontSize: 16 }}>
                          {n.value}
                        </div>
                        <div className="text-gray-400" style={{ fontSize: 11 }}>{n.label}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </SettingsSection>
            )}

            {active === "display" && (
              <SettingsSection title="显示设置">
                <SettingRow label="分辨率" description="远程屏幕分辨率">
                  <ModalSelect
                    value={resolution}
                    options={["自适应", "1920×1080", "2560×1440", "3840×2160"]}
                    onChange={setResolution}
                  />
                </SettingRow>
                <SettingRow label="画质" description="图像压缩质量与速度平衡">
                  <ModalSelect value={quality} options={["高质量", "平衡", "流畅优先"]} onChange={setQuality} />
                </SettingRow>
                <SettingRow label="色彩深度" description="远程屏幕颜色数量">
                  <ModalSelect value={colorDepth} options={["32位", "16位", "8位"]} onChange={setColorDepth} />
                </SettingRow>
                <SettingRow label="显示远程光标" description="在本地显示远程端鼠标位置">
                  <Toggle value={showCursor} onChange={setShowCursor} />
                </SettingRow>
              </SettingsSection>
            )}

            {active === "audio" && (
              <SettingsSection title="音频与输入">
                <SettingRow label="远程音频输出" description="将远程设备音频传输到本地">
                  <Toggle value={audioOutput} onChange={setAudioOutput} />
                </SettingRow>
                <SettingRow label="本地麦克风" description="允许远程端访问本地麦克风">
                  <Toggle value={audioInput} onChange={setAudioInput} />
                </SettingRow>
              </SettingsSection>
            )}

            {active === "notifications" && (
              <SettingsSection title="通知设置">
                <SettingRow label="连接通知" description="有新的远程连接时通知">
                  <Toggle value={notifyConnect} onChange={setNotifyConnect} />
                </SettingRow>
                <SettingRow label="断开通知" description="连接断开时通知">
                  <Toggle value={notifyDisconnect} onChange={setNotifyDisconnect} />
                </SettingRow>
                <SettingRow label="连接请求通知" description="收到连接申请时通知">
                  <Toggle value={notifyRequest} onChange={setNotifyRequest} />
                </SettingRow>
                <SettingRow label="通知音效" description="播放提示音">
                  <Toggle value={sound} onChange={setSound} />
                </SettingRow>
              </SettingsSection>
            )}

            {active === "account" && (
              <SettingsSection title="账户">
                <div
                  className={`flex items-center gap-4 p-4 rounded-xl border mb-5 ${
                    isDark ? "bg-[#2a2a2a] border-gray-700" : "bg-gray-50 border-gray-200"
                  }`}
                >
                  <div
                    className="w-11 h-11 rounded-full bg-gradient-to-br from-purple-500 to-pink-500 flex items-center justify-center text-white font-semibold"
                    style={{ fontSize: 16 }}
                  >
                    U
                  </div>
                  <div>
                    <div className={`font-medium ${isDark ? "text-gray-100" : "text-gray-900"}`} style={{ fontSize: 15 }}>
                      当前用户
                    </div>
                    <div className={isDark ? "text-gray-400" : "text-gray-500"} style={{ fontSize: 12 }}>
                      user@example.com
                    </div>
                    <div
                      className={`inline-flex items-center gap-1 mt-1 px-2 py-0.5 rounded-full ${
                        isDark ? "bg-blue-900/30 text-blue-400" : "bg-blue-50 text-blue-600"
                      }`}
                      style={{ fontSize: 10 }}
                    >
                      免费版
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3 mb-5">
                  {[
                    { label: "升级到专业版", desc: "解锁更多设备与高级功能", isPrimary: true },
                    { label: "修改密码", desc: "更改账户登录密码", isPrimary: false },
                  ].map((btn) => (
                    <button
                      key={btn.label}
                      className={`p-4 rounded-xl border text-left transition-colors ${
                        btn.isPrimary
                          ? "bg-blue-600 hover:bg-blue-500 text-white border-transparent"
                          : isDark
                          ? "bg-[#2a2a2a] hover:bg-[#333] text-gray-300 border-gray-700"
                          : "bg-white hover:bg-gray-50 text-gray-700 border-gray-200"
                      }`}
                    >
                      <div className="font-medium" style={{ fontSize: 13 }}>{btn.label}</div>
                      <div
                        className={`mt-0.5 ${btn.isPrimary ? "text-blue-200" : isDark ? "text-gray-500" : "text-gray-400"}`}
                        style={{ fontSize: 11 }}
                      >
                        {btn.desc}
                      </div>
                    </button>
                  ))}
                </div>

                <div className="space-y-2">
                  <button
                    className={`flex items-center gap-3 w-full px-4 py-3 rounded-xl border transition-colors ${
                      isDark
                        ? "border-gray-700 hover:bg-gray-800 text-gray-400 hover:text-gray-200"
                        : "border-gray-200 hover:bg-gray-50 text-gray-600 hover:text-gray-900"
                    }`}
                    style={{ fontSize: 13 }}
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    退出登录
                  </button>
                  <button
                    className={`flex items-center gap-3 w-full px-4 py-3 rounded-xl border transition-colors ${
                      isDark
                        ? "border-red-800 hover:bg-red-900/20 text-red-400 hover:text-red-300"
                        : "border-red-200 hover:bg-red-50 text-red-400 hover:text-red-600"
                    }`}
                    style={{ fontSize: 13 }}
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    注销账户
                  </button>
                </div>
              </SettingsSection>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function SettingsSection({ title, children }: { title: string; children: React.ReactNode }) {
  const { isDark } = useTheme();
  return (
    <div>
      <h2 className={`mb-4 ${isDark ? "text-gray-100" : "text-gray-900"}`} style={{ fontSize: 16 }}>
        {title}
      </h2>
      <div className="space-y-0.5">{children}</div>
    </div>
  );
}

function SettingRow({
  label,
  description,
  children,
}: {
  label: string;
  description: string;
  children: React.ReactNode;
}) {
  const { isDark } = useTheme();
  return (
    <div
      className={`flex items-center justify-between p-3.5 rounded-xl transition-colors ${
        isDark ? "hover:bg-gray-800/50" : "hover:bg-gray-50"
      }`}
    >
      <div>
        <div className={isDark ? "text-gray-200" : "text-gray-800"} style={{ fontSize: 13 }}>
          {label}
        </div>
        <div className={`mt-0.5 ${isDark ? "text-gray-500" : "text-gray-400"}`} style={{ fontSize: 11 }}>
          {description}
        </div>
      </div>
      <div className="shrink-0 ml-4">{children}</div>
    </div>
  );
}
