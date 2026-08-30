import { useState, useEffect } from "react";
import { useTheme } from "./ThemeContext";
import {
  registerDevice,
  listDevices,
  requestRemoteSession,
  acceptSession,
  stopSession,
  startSender,
  startReceiver,
  getSessionSnapshot,
  type DeviceInfo,
  type SessionRuntimeSnapshot,
  type TransportKind,
} from "../services/ipcSessionService";

interface IpcSessionCardProps {
  onServiceStatusChange?: (status: string) => void;
}

export function IpcSessionCard({ onServiceStatusChange }: IpcSessionCardProps) {
  const { isDark } = useTheme();

  // Device state
  const [registeredDeviceId, setRegisteredDeviceId] = useState<string>("");
  const [deviceName, setDeviceName] = useState<string>("Rdesk Device");

  // Devices list
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [devicesLoading, setDevicesLoading] = useState(false);

  // Session state
  const [sessionId, setSessionId] = useState<string>("test-session-1");
  const [selectedDeviceId, setSelectedDeviceId] = useState<string>("");
  const [transportKind, setTransportKind] = useState<TransportKind>("webrtc");
  const [currentSession, setCurrentSession] = useState<SessionRuntimeSnapshot | null>(null);

  // UI state
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string>("");

  const updateStatus = (msg: string) => {
    setStatusMessage(msg);
    onServiceStatusChange?.(msg);
  };

  // Load devices periodically
  useEffect(() => {
    const loadDevices = async () => {
      setDevicesLoading(true);
      try {
        const devs = await listDevices();
        setDevices(devs);
      } catch (e) {
        console.warn("Failed to load devices:", e);
      } finally {
        setDevicesLoading(false);
      }
    };

    loadDevices();
    const interval = setInterval(loadDevices, 5000);
    return () => clearInterval(interval);
  }, []);

  // Refresh session snapshot
  const refreshSnapshot = async () => {
    if (!currentSession && !sessionId) return;

    try {
      const snapshot = await getSessionSnapshot(sessionId);
      setCurrentSession(snapshot);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to get session snapshot");
    }
  };

  // Auto-refresh snapshot when session is active
  useEffect(() => {
    if (currentSession?.state === "streaming" || currentSession?.state === "connected") {
      const interval = setInterval(refreshSnapshot, 2000);
      return () => clearInterval(interval);
    }
  }, [currentSession?.state, sessionId]);

  const handleRegisterDevice = async () => {
    if (!registeredDeviceId || !deviceName) {
      setError("请输入设备 ID 和名称");
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const deviceId = await registerDevice(registeredDeviceId, deviceName);
      updateStatus(`设备已注册: ${deviceId}`);
      await refreshSnapshot();
    } catch (e) {
      setError(e instanceof Error ? e.message : "设备注册失败");
    } finally {
      setLoading(false);
    }
  };

  const handleStartSession = async () => {
    if (!sessionId || !selectedDeviceId) {
      setError("请输入会话 ID 并选择目标设备");
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const snapshot = await requestRemoteSession(
        sessionId,
        selectedDeviceId,
        transportKind,
        undefined,
        "auto",
      );
      updateStatus(
        `安全会话请求已受理: ${snapshot.session_id} · ${snapshot.presentation_state}`,
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "启动会话失败");
    } finally {
      setLoading(false);
    }
  };

  const handleAcceptSession = async () => {
    if (!sessionId) {
      setError("请输入会话 ID");
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const result = await acceptSession(sessionId, selectedDeviceId || "unknown-source");
      updateStatus(`会话已接受: ${result}`);
      await refreshSnapshot();
    } catch (e) {
      setError(e instanceof Error ? e.message : "接受会话失败");
    } finally {
      setLoading(false);
    }
  };

  const handleStopSession = async () => {
    if (!sessionId && !currentSession) {
      setError("没有活动的会话");
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const id = sessionId || currentSession?.session_id || "";
      const result = await stopSession(id);
      updateStatus(`会话已停止: ${result}`);
      setCurrentSession(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "停止会话失败");
    } finally {
      setLoading(false);
    }
  };

  const handleStartSender = async () => {
    if (!sessionId && !currentSession) {
      setError("没有活动的会话");
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const id = sessionId || currentSession?.session_id || "";
      const result = await startSender(id);
      updateStatus(`发送器已启动: ${result}`);
      await refreshSnapshot();
    } catch (e) {
      setError(e instanceof Error ? e.message : "启动发送器失败");
    } finally {
      setLoading(false);
    }
  };

  const handleStartReceiver = async () => {
    if (!sessionId && !currentSession) {
      setError("没有活动的会话");
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const id = sessionId || currentSession?.session_id || "";
      const result = await startReceiver(id);
      updateStatus(`接收器已启动: ${result}`);
      await refreshSnapshot();
    } catch (e) {
      setError(e instanceof Error ? e.message : "启动接收器失败");
    } finally {
      setLoading(false);
    }
  };

  const getStateColor = (state: string) => {
    switch (state) {
      case "streaming":
      case "connected":
        return "text-green-600";
      case "listening":
      case "connecting":
        return "text-amber-500";
      case "failed":
      case "closed":
        return "text-red-500";
      default:
        return "text-blue-500";
    }
  };

  return (
    <div className={`p-3.5 rounded-xl border mt-3 ${isDark ? "bg-[#2a2a2a] border-gray-700" : "bg-white border-gray-200"}`}>
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className={isDark ? "text-gray-200" : "text-gray-800"} style={{ fontSize: 13 }}>
            IPC Session Control
          </div>
          <div className={`mt-0.5 ${isDark ? "text-gray-500" : "text-gray-400"}`} style={{ fontSize: 11 }}>
            通过 mrd-service IPC 接口管理会话。WebRTC 信令由服务内部处理。
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => void listDevices().then(setDevices)}
            disabled={devicesLoading}
            className={`px-3 py-1.5 rounded-lg border transition-colors ${
              isDark
                ? "border-gray-600 text-gray-300 hover:bg-gray-800 disabled:opacity-50"
                : "border-gray-200 text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            }`}
            style={{ fontSize: 12 }}
          >
            刷新设备
          </button>
          <button
            onClick={() => void refreshSnapshot()}
            disabled={loading || !sessionId}
            className={`px-3 py-1.5 rounded-lg border transition-colors ${
              isDark
                ? "border-gray-600 text-gray-300 hover:bg-gray-800 disabled:opacity-50"
                : "border-gray-200 text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            }`}
            style={{ fontSize: 12 }}
          >
            刷新快照
          </button>
        </div>
      </div>

      {/* Device Registration */}
      <div
        className={`mt-3 rounded-lg border px-3 py-2 ${isDark ? "border-gray-700 bg-[#1f1f1f]" : "border-gray-200 bg-gray-50"}`}
      >
        <div className={isDark ? "text-gray-300" : "text-gray-700"} style={{ fontSize: 12 }}>
          设备注册
        </div>
        <div className="grid grid-cols-2 gap-3 mt-2">
          <label className="flex flex-col gap-1">
            <span className={isDark ? "text-gray-400" : "text-gray-500"} style={{ fontSize: 11 }}>
              本地 Device ID
            </span>
            <input
              value={registeredDeviceId}
              onChange={(e) => setRegisteredDeviceId(e.target.value)}
              placeholder="例如: controller-1"
              className={`px-3 py-2 rounded-lg border outline-none ${
                isDark
                  ? "bg-[#1f1f1f] border-gray-700 text-gray-100"
                  : "bg-white border-gray-200 text-gray-800"
              }`}
              style={{ fontSize: 12 }}
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className={isDark ? "text-gray-400" : "text-gray-500"} style={{ fontSize: 11 }}>
              设备名称
            </span>
            <input
              value={deviceName}
              onChange={(e) => setDeviceName(e.target.value)}
              placeholder="例如: Rdesk Controller"
              className={`px-3 py-2 rounded-lg border outline-none ${
                isDark
                  ? "bg-[#1f1f1f] border-gray-700 text-gray-100"
                  : "bg-white border-gray-200 text-gray-800"
              }`}
              style={{ fontSize: 12 }}
            />
          </label>
        </div>
        <div className="flex gap-2 mt-2">
          <ActionButton isDark={isDark} disabled={loading} onClick={handleRegisterDevice}>
            注册设备
          </ActionButton>
        </div>
      </div>

      {/* Available Devices */}
      {devices.length > 0 && (
        <div
          className={`mt-3 rounded-lg border px-3 py-2 ${isDark ? "border-gray-700 bg-[#1f1f1f]" : "border-gray-200 bg-gray-50"}`}
        >
          <div className={isDark ? "text-gray-300" : "text-gray-700"} style={{ fontSize: 12 }}>
            可用设备 ({devices.length})
          </div>
          <div className="mt-2 space-y-1">
            {devices.map((dev) => (
              <div
                key={dev.device_id}
                className={`flex items-center justify-between px-3 py-2 rounded-lg cursor-pointer transition-colors ${
                  isDark
                    ? "hover:bg-gray-800"
                    : "hover:bg-gray-100"
                } ${selectedDeviceId === dev.device_id ? (isDark ? "bg-blue-900/30" : "bg-blue-50") : ""}`}
                onClick={() => setSelectedDeviceId(dev.device_id)}
              >
                <div>
                  <div className={isDark ? "text-gray-200" : "text-gray-800"} style={{ fontSize: 12 }}>
                    {dev.device_name}
                  </div>
                  <div className={isDark ? "text-gray-500" : "text-gray-400"} style={{ fontSize: 11 }}>
                    {dev.device_id}
                  </div>
                </div>
                <div
                  className={`px-2 py-0.5 rounded-full text-xs ${
                    dev.is_online
                      ? isDark
                        ? "bg-green-900/30 text-green-300"
                        : "bg-green-50 text-green-700"
                      : isDark
                        ? "bg-gray-700 text-gray-400"
                        : "bg-gray-100 text-gray-500"
                  }`}
                >
                  {dev.is_online ? "在线" : "离线"}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Session Control */}
      <div
        className={`mt-3 rounded-lg border px-3 py-2 ${isDark ? "border-gray-700 bg-[#1f1f1f]" : "border-gray-200 bg-gray-50"}`}
      >
        <div className={isDark ? "text-gray-300" : "text-gray-700"} style={{ fontSize: 12 }}>
          会话控制
        </div>
        <div className="grid grid-cols-3 gap-3 mt-2">
          <label className="flex flex-col gap-1">
            <span className={isDark ? "text-gray-400" : "text-gray-500"} style={{ fontSize: 11 }}>
              Session ID
            </span>
            <input
              value={sessionId}
              onChange={(e) => setSessionId(e.target.value)}
              className={`px-3 py-2 rounded-lg border outline-none ${
                isDark
                  ? "bg-[#1f1f1f] border-gray-700 text-gray-100"
                  : "bg-white border-gray-200 text-gray-800"
              }`}
              style={{ fontSize: 12 }}
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className={isDark ? "text-gray-400" : "text-gray-500"} style={{ fontSize: 11 }}>
              传输类型
            </span>
            <select
              value={transportKind}
              onChange={(e) => setTransportKind(e.target.value as TransportKind)}
              className={`px-3 py-2 rounded-lg border outline-none ${
                isDark
                  ? "bg-[#1f1f1f] border-gray-700 text-gray-100"
                  : "bg-white border-gray-200 text-gray-800"
              }`}
              style={{ fontSize: 12 }}
            >
              <option value="webrtc">WebRTC</option>
              <option value="quic">QUIC</option>
            </select>
          </label>
          <label className="flex flex-col gap-1">
            <span className={isDark ? "text-gray-400" : "text-gray-500"} style={{ fontSize: 11 }}>
              目标设备
            </span>
            <select
              value={selectedDeviceId}
              onChange={(e) => setSelectedDeviceId(e.target.value)}
              className={`px-3 py-2 rounded-lg border outline-none ${
                isDark
                  ? "bg-[#1f1f1f] border-gray-700 text-gray-100"
                  : "bg-white border-gray-200 text-gray-800"
              }`}
              style={{ fontSize: 12 }}
            >
              <option value="">选择设备...</option>
              {devices.map((dev) => (
                <option key={dev.device_id} value={dev.device_id}>
                  {dev.device_name}
                </option>
              ))}
            </select>
          </label>
        </div>
        <div className="flex flex-wrap gap-2 mt-2">
          <ActionButton isDark={isDark} disabled={loading} onClick={handleStartSession}>
            启动会话
          </ActionButton>
          <ActionButton isDark={isDark} disabled={loading} onClick={handleAcceptSession}>
            接受会话
          </ActionButton>
          <ActionButton isDark={isDark} disabled={loading} onClick={handleStopSession}>
            停止会话
          </ActionButton>
        </div>
      </div>

      {/* Session Snapshot */}
      {currentSession && (
        <div
          className={`mt-3 rounded-lg border px-3 py-2 ${isDark ? "border-gray-700 bg-[#1f1f1f]" : "border-gray-200 bg-gray-50"}`}
        >
          <div className={isDark ? "text-gray-300" : "text-gray-700"} style={{ fontSize: 12 }}>
            会话快照
          </div>
          <div className="grid grid-cols-3 gap-3 mt-2">
            <SessionMetric label="会话 ID" value={currentSession.session_id} />
            <SessionMetric label="角色" value={currentSession.role} />
            <SessionMetric
              label="状态"
              value={currentSession.state}
              valueClass={getStateColor(currentSession.state)}
            />
            <SessionMetric label="传输类型" value={currentSession.transport_kind} />
            <SessionMetric label="发送器" value={currentSession.sender_active ? "运行中" : "未启动"} />
            <SessionMetric label="接收器" value={currentSession.receiver_active ? "运行中" : "未启动"} />
          </div>
          {currentSession.last_error && (
            <div
              className={`mt-2 px-3 py-2 rounded-lg ${isDark ? "bg-red-900/20 text-red-300" : "bg-red-50 text-red-600"}`}
              style={{ fontSize: 11 }}
            >
              错误: {currentSession.last_error}
            </div>
          )}
        </div>
      )}

      {/* Media Control */}
      <div
        className={`mt-3 rounded-lg border px-3 py-2 ${isDark ? "border-gray-700 bg-[#1f1f1f]" : "border-gray-200 bg-gray-50"}`}
      >
        <div className={isDark ? "text-gray-300" : "text-gray-700"} style={{ fontSize: 12 }}>
          媒体控制
        </div>
        <div className="flex flex-wrap gap-2 mt-2">
          <ActionButton isDark={isDark} disabled={loading} onClick={handleStartSender}>
            启动发送器
          </ActionButton>
          <ActionButton isDark={isDark} disabled={loading} onClick={handleStartReceiver}>
            启动接收器
          </ActionButton>
        </div>
      </div>

      {/* Status and Error */}
      {statusMessage && (
        <div
          className={`mt-3 rounded-lg px-3 py-2 ${isDark ? "bg-blue-900/20 text-blue-300" : "bg-blue-50 text-blue-700"}`}
          style={{ fontSize: 12 }}
        >
          {statusMessage}
        </div>
      )}

      {error && (
        <div
          className={`mt-3 rounded-lg px-3 py-2 ${isDark ? "bg-red-900/20 text-red-300" : "bg-red-50 text-red-600"}`}
          style={{ fontSize: 12 }}
        >
          {error}
        </div>
      )}
    </div>
  );
}

function SessionMetric({
  label,
  value,
  valueClass,
}: {
  label: string;
  value: string;
  valueClass?: string;
}) {
  const { isDark } = useTheme();

  return (
    <div className={`rounded-lg border px-3 py-2 ${isDark ? "border-gray-700 bg-[#1d1d1d]" : "border-gray-200 bg-white"}`}>
      <div className={isDark ? "text-gray-500" : "text-gray-400"} style={{ fontSize: 11 }}>
        {label}
      </div>
      <div className={isDark ? "text-gray-100" : "text-gray-800"} style={{ fontSize: 13 }}>
        <span className={valueClass || ""}>{value || "-"}</span>
      </div>
    </div>
  );
}

function ActionButton({
  isDark,
  disabled,
  onClick,
  children,
}: {
  isDark: boolean;
  disabled: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`px-3 py-1.5 rounded-lg border transition-colors ${
        isDark
          ? "border-gray-600 text-gray-300 hover:bg-gray-800 disabled:opacity-50"
          : "border-gray-200 text-gray-700 hover:bg-gray-50 disabled:opacity-50"
      }`}
      style={{ fontSize: 12 }}
    >
      {children}
    </button>
  );
}
