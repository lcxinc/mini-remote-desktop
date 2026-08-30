import { useState, useEffect } from "react";
import {
  X,
  Mail,
  Lock,
  User,
  Eye,
  EyeOff,
  QrCode,
  Smartphone,
  Check,
  Shield,
} from "lucide-react";
import { useTheme } from "./ThemeContext";
import { useAuth } from "./AuthContext";
import { deviceService } from "../services/deviceService";

interface AuthModalProps {
  open: boolean;
  onClose: () => void;
}

type AuthMode = "login" | "register";
type LoginMethod = "account" | "qrcode";
type LoginResponse = {
  access_token: string;
  token_type: string;
  user_id: string;
  username: string;
  role: string;
};
type RegisterPayload = {
  username: string;
  email: string;
  password: string;
};

const API_BASE =
  (import.meta as any).env?.VITE_RDESK_SERVER_URL ?? "http://127.0.0.1:9530/api/v1";

export function AuthModal({ open, onClose }: AuthModalProps) {
  const { isDark } = useTheme();
  const { login } = useAuth();
  const [visible, setVisible] = useState(false);
  const [mode, setMode] = useState<AuthMode>("login");
  const [loginMethod, setLoginMethod] = useState<LoginMethod>("account");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [qrStatus, setQrStatus] = useState<"waiting" | "scanned" | "expired">("waiting");
  const [qrTimer, setQrTimer] = useState(120);
  const [rememberMe, setRememberMe] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [authSuccess, setAuthSuccess] = useState<string | null>(null);
  const [contentKey, setContentKey] = useState("login-account"); // For animation

  // Form state
  const [loginAccount, setLoginAccount] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [username, setUsername] = useState("");

  // Update content key when mode or login method changes
  useEffect(() => {
    setContentKey(`${mode}-${loginMethod}`);
  }, [mode, loginMethod]);

  useEffect(() => {
    if (open) {
      requestAnimationFrame(() => setVisible(true));
    } else {
      setVisible(false);
    }
  }, [open]);

  // QR code countdown
  useEffect(() => {
    if (!open || loginMethod !== "qrcode" || qrStatus !== "waiting") return;
    const interval = setInterval(() => {
      setQrTimer((t) => {
        if (t <= 1) {
          setQrStatus("expired");
          return 0;
        }
        return t - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [open, loginMethod, qrStatus]);

  const resetQr = () => {
    setQrStatus("waiting");
    setQrTimer(120);
  };

  const switchMode = (newMode: AuthMode) => {
    setMode(newMode);
    setLoginMethod("account");
    setShowPassword(false);
    setShowConfirmPassword(false);
    setAuthError(null);
    setAuthSuccess(null);
  };

  const handleLogin = async () => {
    if (!loginAccount.trim() || !password.trim()) {
      setAuthError("请输入账号和密码");
      return;
    }
    setSubmitting(true);
    setAuthError(null);
    setAuthSuccess(null);
    try {
      const resp = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: loginAccount.trim(),
          password,
        }),
      });
      if (!resp.ok) {
        const detail = await resp.json().catch(() => ({}));
        throw new Error(detail?.detail || `登录失败 (${resp.status})`);
      }
      const data = (await resp.json()) as LoginResponse;

      // 使用 AuthContext 的 login 方法
      login(data.access_token, {
        id: data.user_id,
        username: data.username,
        role: data.role,
      });

      // 绑定设备（如果设备已注册）
      try {
        const bindResult = await deviceService.bindDevice(data.user_id);
        if (bindResult.success && bindResult.kickedUser) {
          console.log("[Auth] 设备从其他用户迁移:", bindResult.kickedUser);
        }
      } catch (err) {
        console.warn("[Auth] 设备绑定失败，但不影响登录:", err);
      }

      onClose();
    } catch (e) {
      setAuthError(e instanceof Error ? e.message : "登录失败");
    } finally {
      setSubmitting(false);
    }
  };

  const handleRegister = async () => {
    const usernameValue = username.trim();
    const emailValue = email.trim().toLowerCase();

    if (!usernameValue || !emailValue || !password || !confirmPassword) {
      setAuthError("请完整填写注册信息");
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailValue)) {
      setAuthError("请输入有效邮箱地址");
      return;
    }
    if (usernameValue.length < 3) {
      setAuthError("用户名至少 3 位");
      return;
    }
    if (password.length < 8) {
      setAuthError("密码至少 8 位");
      return;
    }
    if (password !== confirmPassword) {
      setAuthError("两次输入的密码不一致");
      return;
    }
    if (!rememberMe) {
      setAuthError("请先同意服务协议和隐私政策");
      return;
    }

    setSubmitting(true);
    setAuthError(null);
    setAuthSuccess(null);
    try {
      const payload: RegisterPayload = {
        username: usernameValue,
        email: emailValue,
        password,
      };
      const resp = await fetch(`${API_BASE}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!resp.ok) {
        const detail = await resp.json().catch(() => ({}));
        throw new Error(detail?.detail || `注册失败 (${resp.status})`);
      }
      await resp.json();

      // 注册成功，显示提示
      setAuthSuccess("注册成功！正在跳转登录...");

      // 延迟后自动切换到登录界面
      setTimeout(() => {
        setMode("login");
        setLoginMethod("account");
        setLoginAccount(usernameValue);
        setPassword(payload.password);
        setConfirmPassword("");
        setAuthSuccess(null);
      }, 1500);
    } catch (e) {
      setAuthError(e instanceof Error ? e.message : "注册失败");
    } finally {
      setSubmitting(false);
    }
  };

  if (!open && !visible) return null;

  const overlay = isDark ? "bg-black/60" : "bg-black/30";
  const card = isDark ? "bg-[#1e1e1e] border-gray-700 shadow-[0_12px_40px_rgba(0,0,0,0.5)]" : "bg-white border-gray-200/80 shadow-[0_12px_40px_rgba(0,0,0,0.12),0_4px_12px_rgba(0,0,0,0.06)]";
  const textPrimary = isDark ? "text-gray-100" : "text-gray-900";
  const textSecondary = isDark ? "text-gray-400" : "text-gray-500";
  const textTertiary = isDark ? "text-gray-500" : "text-gray-400";
  const inputStyle = isDark
    ? "bg-[#2a2a2a] border-gray-600 text-gray-200 placeholder-gray-500 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20"
    : "bg-gray-50 border-gray-200 text-gray-900 placeholder-gray-400 focus:border-blue-400 focus:ring-2 focus:ring-blue-100";
  const divider = isDark ? "bg-gray-700" : "bg-gray-200";
  const hoverBg = isDark ? "hover:bg-gray-700" : "hover:bg-gray-50";

  return (
    <div
      className={`fixed inset-0 z-50 flex items-center justify-center transition-opacity duration-200 ${
        visible && open ? "opacity-100" : "opacity-0 pointer-events-none"
      } ${overlay}`}
    >
      <div
        className={`relative rounded-2xl border transition-all duration-200 overflow-hidden ${
          visible && open ? "scale-100" : "scale-95"
        } ${card}`}
        style={{ width: 420 }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Close button */}
        <button
          onClick={onClose}
          className={`absolute right-3 top-3 z-10 p-1.5 rounded-lg transition-colors ${
            isDark ? "text-gray-400 hover:text-gray-200 hover:bg-gray-700" : "text-gray-400 hover:text-gray-600 hover:bg-gray-100"
          }`}
        >
          <X className="w-4 h-4" />
        </button>

        {/* Header / Brand */}
        <div className="px-8 pt-8 pb-2 text-center">
          <div className="flex items-center justify-center gap-2 mb-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-yellow-400 to-yellow-600 flex items-center justify-center shadow-sm">
              <Shield className="w-4.5 h-4.5 text-white" style={{ width: 18, height: 18 }} />
            </div>
          </div>
          <h2 className={textPrimary} style={{ fontSize: 18 }}>
            {mode === "login" ? "登录 R-Desk" : "创建账户"}
          </h2>
          <p className={`mt-1 ${textSecondary}`} style={{ fontSize: 13 }}>
            {mode === "login"
              ? "安全连接，随时随地远程控制你的设备"
              : "注册后即可管理和远程控制你的所有设备"}
          </p>
        </div>

        {/* Login method toggle (only in login mode) */}
        {mode === "login" && (
          <div className="px-8 pt-3">
            <div className={`flex items-center gap-1 p-1 rounded-xl ${isDark ? "bg-[#2a2a2a]" : "bg-gray-100"}`}>
              <button
                onClick={() => setLoginMethod("account")}
                className={`flex-1 flex items-center justify-center gap-1.5 py-2 rounded-lg border transition-all ${
                  loginMethod === "account"
                    ? isDark
                      ? "bg-[#232323] text-gray-100 shadow-sm border-gray-600"
                      : "bg-white text-gray-900 shadow-sm border-gray-200"
                    : isDark
                      ? "text-gray-400 hover:text-gray-200 border-transparent"
                      : "text-gray-500 hover:text-gray-700 border-transparent"
                }`}
                style={{ fontSize: 13 }}
              >
                <Mail className="w-3.5 h-3.5" />
                账号登录
              </button>
              <button
                onClick={() => { setLoginMethod("qrcode"); resetQr(); }}
                className={`flex-1 flex items-center justify-center gap-1.5 py-2 rounded-lg border transition-all ${
                  loginMethod === "qrcode"
                    ? isDark
                      ? "bg-[#232323] text-gray-100 shadow-sm border-gray-600"
                      : "bg-white text-gray-900 shadow-sm border-gray-200"
                    : isDark
                      ? "text-gray-400 hover:text-gray-200 border-transparent"
                      : "text-gray-500 hover:text-gray-700 border-transparent"
                }`}
                style={{ fontSize: 13 }}
              >
                <QrCode className="w-3.5 h-3.5" />
                扫码登录
              </button>
            </div>
          </div>
        )}

        {/* Content area with animated transitions */}
        <div className="px-8 pt-5 pb-6 overflow-hidden">
          <div
            key={contentKey}
            className="transition-all duration-300 ease-out"
            style={{
              animation: "fadeInSlideUp 0.3s ease-out",
            }}
          >
          {/* Account login form */}
          {(mode === "login" && loginMethod === "account") && (
            <div className="space-y-3.5">
              {/* Account */}
              <div>
                <label className={`block mb-1.5 ${textSecondary}`} style={{ fontSize: 12 }}>账号</label>
                <div className="relative">
                  <Mail className={`absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 ${textTertiary}`} />
                  <input
                    type="text"
                    value={loginAccount}
                    onChange={(e) => setLoginAccount(e.target.value)}
                    placeholder="请输入账号"
                    className={`w-full pl-10 pr-3 py-2.5 rounded-lg border outline-none transition-all ${inputStyle}`}
                    style={{ fontSize: 13 }}
                  />
                </div>
              </div>

              {/* Password */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className={textSecondary} style={{ fontSize: 12 }}>密码</label>
                  <button className="text-blue-500 hover:text-blue-400 transition-colors" style={{ fontSize: 12 }}>
                    忘记密码？
                  </button>
                </div>
                <div className="relative">
                  <Lock className={`absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 ${textTertiary}`} />
                  <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="输入密码"
                    className={`w-full pl-10 pr-10 py-2.5 rounded-lg border outline-none transition-all ${inputStyle}`}
                    style={{ fontSize: 13 }}
                  />
                  <button
                    onClick={() => setShowPassword(!showPassword)}
                    className={`absolute right-3 top-1/2 -translate-y-1/2 ${textTertiary} hover:text-gray-300 transition-colors`}
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Remember me */}
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setRememberMe(!rememberMe)}
                  className={`w-4 h-4 rounded border flex items-center justify-center transition-colors ${
                    rememberMe
                      ? "bg-blue-600 border-blue-600"
                      : isDark ? "border-gray-600 bg-transparent" : "border-gray-300 bg-transparent"
                  }`}
                >
                  {rememberMe && <Check className="w-3 h-3 text-white" />}
                </button>
                <span className={textSecondary} style={{ fontSize: 12 }}>记住我的登录状态</span>
              </div>

              {/* Submit */}
              <button
                onClick={() => void handleLogin()}
                disabled={submitting}
                className="w-full py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors shadow-sm font-medium disabled:opacity-60"
                style={{ fontSize: 14 }}
              >
                {submitting ? "登录中..." : "登 录"}
              </button>

              {authError && (
                <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/20 text-red-500 text-center" style={{ fontSize: 12 }}>
                  {authError}
                </div>
              )}
              {authSuccess && (
                <div className="p-2 rounded-lg bg-green-500/10 border border-green-500/20 text-green-600 text-center" style={{ fontSize: 12 }}>
                  {authSuccess}
                </div>
              )}

              {/* Divider */}
              <div className="flex items-center gap-3 py-1">
                <div className={`flex-1 h-px ${divider}`} />
                <span className={textTertiary} style={{ fontSize: 11 }}>或</span>
                <div className={`flex-1 h-px ${divider}`} />
              </div>

              {/* Social login */}
              <div className="flex items-center gap-2">
                {[
                  { label: "微信", color: "bg-green-600 hover:bg-green-500", icon: "W" },
                  { label: "GitHub", color: isDark ? "bg-gray-700 hover:bg-gray-600" : "bg-gray-800 hover:bg-gray-700", icon: "G" },
                  { label: "Google", color: isDark ? "bg-gray-700 hover:bg-gray-600" : "bg-white hover:bg-gray-50 border border-gray-200", icon: "G", textColor: isDark ? "text-white" : "text-gray-700" },
                ].map((s) => (
                  <button
                    key={s.label}
                    className={`flex-1 flex items-center justify-center gap-1.5 py-2 rounded-lg transition-colors text-white ${s.color} ${s.textColor || ""}`}
                    style={{ fontSize: 12 }}
                  >
                    <span className="font-bold" style={{ fontSize: 13 }}>{s.icon}</span>
                    {s.label}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* QR Code login */}
          {(mode === "login" && loginMethod === "qrcode") && (
            <div className="flex flex-col items-center">
              {/* QR code placeholder */}
              <div className={`relative w-48 h-48 rounded-2xl border-2 border-dashed flex items-center justify-center mb-4 ${
                qrStatus === "expired"
                  ? "border-red-300 bg-red-50/30"
                  : qrStatus === "scanned"
                    ? "border-green-300 bg-green-50/30"
                    : isDark ? "border-gray-600 bg-[#2a2a2a]" : "border-gray-200 bg-gray-50"
              }`}>
                <div className="text-center px-4">
                  <QrCode className={`w-10 h-10 mx-auto mb-3 ${textTertiary}`} />
                  <div className={textPrimary} style={{ fontSize: 13 }}>
                    扫码登录暂未接入服务端
                  </div>
                  <div className={`${textTertiary} mt-1`} style={{ fontSize: 11 }}>
                    请先使用账号密码登录
                  </div>
                </div>
              </div>

              {/* Instructions */}
              <div className="flex items-center gap-2 mb-2">
                <Smartphone className={`w-4 h-4 ${textTertiary}`} />
                <span className={textSecondary} style={{ fontSize: 13 }}>
                  移动端扫码登录将后续提供
                </span>
              </div>
            </div>
          )}

          {/* Register form */}
          {mode === "register" && (
            <div className="space-y-3.5">
              {/* Username */}
              <div>
                <label className={`block mb-1.5 ${textSecondary}`} style={{ fontSize: 12 }}>用户名</label>
                <div className="relative">
                  <User className={`absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 ${textTertiary}`} />
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="输入用户名"
                    className={`w-full pl-10 pr-3 py-2.5 rounded-lg border outline-none transition-all ${inputStyle}`}
                    style={{ fontSize: 13 }}
                  />
                </div>
              </div>

              {/* Email */}
              <div>
                <label className={`block mb-1.5 ${textSecondary}`} style={{ fontSize: 12 }}>邮箱地址</label>
                <div className="relative">
                  <Mail className={`absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 ${textTertiary}`} />
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="name@example.com"
                    className={`w-full pl-10 pr-3 py-2.5 rounded-lg border outline-none transition-all ${inputStyle}`}
                    style={{ fontSize: 13 }}
                  />
                </div>
              </div>

              {/* Password */}
              <div>
                <label className={`block mb-1.5 ${textSecondary}`} style={{ fontSize: 12 }}>密码</label>
                <div className="relative">
                  <Lock className={`absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 ${textTertiary}`} />
                  <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="至少 8 位，含字母和数字"
                    className={`w-full pl-10 pr-10 py-2.5 rounded-lg border outline-none transition-all ${inputStyle}`}
                    style={{ fontSize: 13 }}
                  />
                  <button
                    onClick={() => setShowPassword(!showPassword)}
                    className={`absolute right-3 top-1/2 -translate-y-1/2 ${textTertiary} hover:text-gray-300 transition-colors`}
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                {/* Password strength indicator */}
                {password.length > 0 && (
                  <div className="flex items-center gap-1.5 mt-2">
                    {[1, 2, 3, 4].map((level) => {
                      const strength = password.length >= 12 ? 4 : password.length >= 8 ? 3 : password.length >= 6 ? 2 : 1;
                      const colors = ["bg-red-500", "bg-yellow-500", "bg-blue-500", "bg-green-500"];
                      return (
                        <div
                          key={level}
                          className={`flex-1 h-1 rounded-full transition-colors ${
                            level <= strength ? colors[strength - 1] : isDark ? "bg-gray-700" : "bg-gray-200"
                          }`}
                        />
                      );
                    })}
                    <span className={textTertiary} style={{ fontSize: 10 }}>
                      {password.length >= 12 ? "强" : password.length >= 8 ? "中" : password.length >= 6 ? "弱" : "太短"}
                    </span>
                  </div>
                )}
              </div>

              {/* Confirm password */}
              <div>
                <label className={`block mb-1.5 ${textSecondary}`} style={{ fontSize: 12 }}>确认密码</label>
                <div className="relative">
                  <Lock className={`absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 ${textTertiary}`} />
                  <input
                    type={showConfirmPassword ? "text" : "password"}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="再次输入密码"
                    className={`w-full pl-10 pr-10 py-2.5 rounded-lg border outline-none transition-all ${inputStyle}`}
                    style={{ fontSize: 13 }}
                  />
                  <button
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                    className={`absolute right-3 top-1/2 -translate-y-1/2 ${textTertiary} hover:text-gray-300 transition-colors`}
                  >
                    {showConfirmPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                {confirmPassword.length > 0 && password !== confirmPassword && (
                  <div className="text-red-500 mt-1" style={{ fontSize: 11 }}>两次输入的密码不一致</div>
                )}
              </div>

              {/* Terms */}
              <div className="flex items-start gap-2">
                <button
                  onClick={() => setRememberMe(!rememberMe)}
                  className={`w-4 h-4 rounded border flex items-center justify-center transition-colors mt-0.5 shrink-0 ${
                    rememberMe
                      ? "bg-blue-600 border-blue-600"
                      : isDark ? "border-gray-600 bg-transparent" : "border-gray-300 bg-transparent"
                  }`}
                >
                  {rememberMe && <Check className="w-3 h-3 text-white" />}
                </button>
                <span className={textSecondary} style={{ fontSize: 12 }}>
                  我已阅读并同意{" "}
                  <button className="text-blue-500 hover:text-blue-400">服务协议</button>
                  {" "}和{" "}
                  <button className="text-blue-500 hover:text-blue-400">隐私政策</button>
                </span>
              </div>

              {/* Submit */}
              <button
                onClick={() => void handleRegister()}
                disabled={submitting}
                className="w-full py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors shadow-sm font-medium disabled:opacity-60"
                style={{ fontSize: 14 }}
              >
                {submitting ? "注册中..." : "注 册"}
              </button>

              {authError && (
                <div className="text-red-500" style={{ fontSize: 12 }}>
                  {authError}
                </div>
              )}
              {authSuccess && (
                <div className="text-green-600" style={{ fontSize: 12 }}>
                  {authSuccess}
                </div>
              )}
            </div>
          )}
          </div>
        </div>

        {/* Footer: switch mode */}
        <div className={`flex items-center justify-center gap-1.5 py-4 border-t ${isDark ? "border-gray-700" : "border-gray-100"}`}>
          <span className={textTertiary} style={{ fontSize: 13 }}>
            {mode === "login" ? "还没有账户？" : "已有账户？"}
          </span>
          <button
            onClick={() => switchMode(mode === "login" ? "register" : "login")}
            className="text-blue-500 hover:text-blue-400 transition-colors font-medium"
            style={{ fontSize: 13 }}
          >
            {mode === "login" ? "立即注册" : "返回登录"}
          </button>
        </div>
      </div>
    </div>
  );
}
