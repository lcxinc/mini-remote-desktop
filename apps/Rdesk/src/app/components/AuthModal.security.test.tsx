import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { AuthModal } from "./AuthModal";

vi.mock("./ThemeContext", () => ({
  useTheme: () => ({ isDark: false }),
}));

vi.mock("./AuthContext", () => ({
  useAuth: () => ({ login: vi.fn() }),
}));

vi.mock("../services/deviceService", () => ({
  deviceService: { bindDevice: vi.fn() },
}));

describe("AuthModal credential safety", () => {
  it("opens with empty credentials and no default-account autofill control", () => {
    render(<AuthModal open onClose={vi.fn()} />);

    expect(screen.getByPlaceholderText("请输入账号")).toHaveValue("");
    expect(screen.getByPlaceholderText("输入密码")).toHaveValue("");
    expect(screen.queryByText("默认账户")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "填入" })).not.toBeInTheDocument();
  });
});
