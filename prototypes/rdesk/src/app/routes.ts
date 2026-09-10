import { createBrowserRouter } from "react-router";
import { Layout } from "./components/Layout";
import { HomePage } from "./components/HomePage";
import { DevicesPage } from "./components/DevicesPage";
import { DeviceDetailPage } from "./components/DeviceDetailPage";
import { RemoteSessionPage } from "./components/RemoteSessionPage";

export const router = createBrowserRouter([
  {
    path: "/session/:id",
    Component: RemoteSessionPage,
  },
  {
    path: "/",
    Component: Layout,
    children: [
      { index: true, Component: HomePage },
      { path: "devices", Component: DevicesPage },
      { path: "devices/:id", Component: DeviceDetailPage },
      { path: "*", Component: HomePage },
    ],
  },
]);