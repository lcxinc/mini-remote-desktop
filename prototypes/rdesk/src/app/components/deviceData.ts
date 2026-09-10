import {
  Monitor,
  Laptop,
  Server,
  Smartphone,
} from "lucide-react";

export interface Device {
  id: string;
  name: string;
  deviceId: string;
  os: string;
  icon: typeof Monitor;
  status: "online" | "offline";
  location: string;
  ping: number | null;
  lastSeen: string;
  cpu: number | null;
  ram: number | null;
  disk: number | null;
  ip: string;
  group: string;
  favorite: boolean;
}

export const devices: Device[] = [
  {
    id: "1",
    name: "办公室电脑",
    deviceId: "821 456 789",
    os: "Windows 11 Pro",
    icon: Monitor,
    status: "online",
    location: "北京",
    ping: 18,
    lastSeen: "在线",
    cpu: 34,
    ram: 68,
    disk: 45,
    ip: "192.168.1.101",
    group: "工作",
    favorite: true,
  },
  {
    id: "2",
    name: "家用 MacBook",
    deviceId: "334 902 115",
    os: "macOS Sonoma 14.2",
    icon: Laptop,
    status: "online",
    location: "上海",
    ping: 35,
    lastSeen: "在线",
    cpu: 12,
    ram: 42,
    disk: 61,
    ip: "192.168.0.5",
    group: "个人",
    favorite: true,
  },
  {
    id: "3",
    name: "Linux 服务器",
    deviceId: "567 234 891",
    os: "Ubuntu 22.04 LTS",
    icon: Server,
    status: "offline",
    location: "深圳",
    ping: null,
    lastSeen: "2小时前",
    cpu: null,
    ram: null,
    disk: null,
    ip: "10.0.0.15",
    group: "服务器",
    favorite: false,
  },
  {
    id: "4",
    name: "测试工作站",
    deviceId: "902 341 567",
    os: "Windows 10",
    icon: Monitor,
    status: "offline",
    location: "杭州",
    ping: null,
    lastSeen: "1天前",
    cpu: null,
    ram: null,
    disk: null,
    ip: "172.16.0.22",
    group: "工作",
    favorite: false,
  },
  {
    id: "5",
    name: "iPhone 15 Pro",
    deviceId: "198 774 302",
    os: "iOS 17.2",
    icon: Smartphone,
    status: "offline",
    location: "广州",
    ping: null,
    lastSeen: "3天前",
    cpu: null,
    ram: null,
    disk: null,
    ip: "—",
    group: "个人",
    favorite: false,
  },
];
