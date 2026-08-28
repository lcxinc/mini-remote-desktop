import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { RemoteSessionModal } from "./RemoteSessionModal";

const device = {
  name: "Office desktop",
  id: "device-1",
  os: "Windows",
};

describe("RemoteSessionModal route preference", () => {
  it("offers Auto, LAN, and WAN Relay and defaults to Auto", () => {
    render(
      <RemoteSessionModal
        device={device}
        onClose={vi.fn()}
        onRoutePreferenceChange={vi.fn()}
      />,
    );

    expect(
      screen.getByRole("radiogroup", { name: "Connection route" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: "Auto" })).toBeChecked();
    expect(screen.getByRole("radio", { name: "LAN" })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: "WAN Relay" })).toBeInTheDocument();
  });

  it("emits only the selected route enum and no connection secrets", async () => {
    const user = userEvent.setup();
    const onRoutePreferenceChange = vi.fn();

    render(
      <RemoteSessionModal
        device={device}
        onClose={vi.fn()}
        onRoutePreferenceChange={onRoutePreferenceChange}
      />,
    );

    await user.click(screen.getByRole("radio", { name: "WAN Relay" }));

    expect(onRoutePreferenceChange).toHaveBeenCalledTimes(1);
    expect(onRoutePreferenceChange).toHaveBeenCalledWith("wan_relay");
    expect(onRoutePreferenceChange.mock.calls[0]).toHaveLength(1);
    expect(
      screen.queryByText(/url|token|secret|credential/i),
    ).not.toBeInTheDocument();
  });
});
