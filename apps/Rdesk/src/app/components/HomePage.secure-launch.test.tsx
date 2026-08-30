import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { HomePage } from "./HomePage";

const mocks = vi.hoisted(() => ({
  launchRemoteDisplayForDevice: vi.fn(),
  navigate: vi.fn(),
}));

vi.mock("react-router", () => ({
  useNavigate: () => mocks.navigate,
}));

vi.mock("./ThemeContext", () => ({
  useTheme: () => ({ isDark: false }),
}));

vi.mock("../services/accessPasswordService", () => ({
  REFRESH_OPTIONS: [],
  useAccessPassword: () => ({
    password: "TEST_ONLY_PASSWORD",
    loading: false,
    refreshing: false,
    refreshMode: "manual",
    refreshPassword: vi.fn(),
    updatePassword: vi.fn(),
    setRefreshMode: vi.fn(),
  }),
}));

vi.mock("../services/deviceService", () => ({
  deviceService: { renameDevice: vi.fn() },
  useDeviceRegistration: () => ({
    deviceId: "local-device",
    deviceName: "Local PC",
  }),
}));

vi.mock("../services/remoteDisplayLauncher", () => ({
  launchRemoteDisplayForDevice: mocks.launchRemoteDisplayForDevice,
}));

describe("HomePage secure remote launch", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.launchRemoteDisplayForDevice.mockResolvedValue({
      sessionId: "secure-session",
      windowLabel: null,
      mode: "route",
    });
  });

  it("requests an authenticated Auto session for a known recent device", async () => {
    const user = userEvent.setup();
    render(<HomePage />);

    await user.click(screen.getByText("办公室电脑"));

    expect(mocks.launchRemoteDisplayForDevice).toHaveBeenCalledWith(
      "821456789",
      expect.objectContaining({
        targetDeviceName: "办公室电脑",
        targetOs: "Windows 11",
        routePreference: "auto",
      }),
    );
    expect(mocks.navigate).toHaveBeenCalledWith("/session/secure-session");
  });

  it("does not offer an ignored remote password credential", () => {
    render(<HomePage />);

    expect(screen.queryByText("密码（可选）")).not.toBeInTheDocument();
    expect(screen.getByText("目标设备确认授权")).toBeInTheDocument();
  });

  it("never turns a custom device id into a direct session route", async () => {
    const user = userEvent.setup();
    render(<HomePage />);

    await user.type(
      screen.getByPlaceholderText("例如：821 456 789"),
      "900 123 456",
    );
    await user.click(screen.getByRole("button", { name: "立即连接" }));

    expect(mocks.launchRemoteDisplayForDevice).toHaveBeenCalledWith(
      "900123456",
      expect.objectContaining({ routePreference: "auto" }),
    );
    expect(mocks.navigate).toHaveBeenCalledWith("/session/secure-session");
    expect(mocks.navigate).not.toHaveBeenCalledWith(
      expect.stringContaining("/session/custom"),
    );
  });

  it("coalesces repeated clicks while one secure request is pending", async () => {
    const user = userEvent.setup();
    let resolveLaunch!: (value: {
      sessionId: string;
      windowLabel: null;
      mode: "route";
    }) => void;
    mocks.launchRemoteDisplayForDevice.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveLaunch = resolve;
        }),
    );
    render(<HomePage />);

    await user.dblClick(screen.getByText("办公室电脑"));

    expect(mocks.launchRemoteDisplayForDevice).toHaveBeenCalledTimes(1);
    resolveLaunch({
      sessionId: "secure-session",
      windowLabel: null,
      mode: "route",
    });
    await vi.waitFor(() => {
      expect(mocks.navigate).toHaveBeenCalledWith("/session/secure-session");
    });
  });
});
