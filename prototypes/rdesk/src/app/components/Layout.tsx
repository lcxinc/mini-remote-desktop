import { Outlet } from "react-router";
import { Sidebar } from "./Sidebar";
import { TitleBar } from "./TitleBar";
import { ConnectionsModal } from "./ConnectionsModal";
import { SettingsModal } from "./SettingsModal";
import { TransferModal } from "./FileTransferPage";
import { AuthModal } from "./AuthModal";
import { useState } from "react";
import { useTheme } from "./ThemeContext";
import { DetailBarProvider } from "./DetailBarContext";

export function Layout() {
  const [collapsed, setCollapsed] = useState(false);
  const [showConnections, setShowConnections] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [showTransfers, setShowTransfers] = useState(false);
  const [showAuth, setShowAuth] = useState(false);
  const { isDark } = useTheme();

  return (
    <DetailBarProvider>
    <div
      className={`flex flex-col h-screen w-screen overflow-hidden rounded-lg border shadow-2xl ${
        isDark
          ? "dark bg-[#1a1a1a] text-gray-100 border-gray-700"
          : "bg-[#f0f2f5] text-gray-900 border-gray-300"
      }`}
    >
      {/* Body: Sidebar full-height + Right (TitleBar + Content) */}
      <div className="flex flex-1 overflow-hidden">
        <Sidebar
          collapsed={collapsed}
          onOpenConnections={() => setShowConnections(true)}
          onOpenSettings={() => setShowSettings(true)}
        />
        <div className="flex flex-col flex-1 overflow-hidden">
          <TitleBar
            onOpenConnections={() => setShowConnections(true)}
            onOpenSettings={() => setShowSettings(true)}
            onOpenTransfers={() => setShowTransfers(true)}
            onOpenAuth={() => setShowAuth(true)}
            collapsed={collapsed}
            onToggleSidebar={() => setCollapsed(!collapsed)}
          />
          <main className="flex-1 overflow-y-auto overflow-x-hidden">
            <Outlet />
          </main>
        </div>
      </div>

      {/* Modals */}
      <ConnectionsModal open={showConnections} onClose={() => setShowConnections(false)} />
      <SettingsModal open={showSettings} onClose={() => setShowSettings(false)} />
      <TransferModal open={showTransfers} onClose={() => setShowTransfers(false)} />
      <AuthModal open={showAuth} onClose={() => setShowAuth(false)} />
    </div>
    </DetailBarProvider>
  );
}