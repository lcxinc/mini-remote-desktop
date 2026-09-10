import { createContext, useContext, useState, useCallback, type ReactNode, type ComponentType } from "react";

export interface DetailBarTab {
  key: string;
  label: string;
  icon: ComponentType<{ style?: React.CSSProperties; className?: string }>;
}

export interface DetailBarPayload {
  deviceName: string;
  deviceIcon: ComponentType<{ style?: React.CSSProperties; className?: string }>;
  isOnline: boolean;
  ping: number | null;
  tabs: DetailBarTab[];
  activeTab: string;
  setActiveTab: (key: string) => void;
  onNavigateBack: () => void;
}

interface DetailBarContextType {
  collapsed: boolean;
  payload: DetailBarPayload | null;
  collapse: (payload: DetailBarPayload) => void;
  expand: () => void;
  reset: () => void;
}

const DetailBarContext = createContext<DetailBarContextType>({
  collapsed: false,
  payload: null,
  collapse: () => {},
  expand: () => {},
  reset: () => {},
});

export function useDetailBar() {
  return useContext(DetailBarContext);
}

export function DetailBarProvider({ children }: { children: ReactNode }) {
  const [collapsed, setCollapsed] = useState(false);
  const [payload, setPayload] = useState<DetailBarPayload | null>(null);

  const collapse = useCallback((p: DetailBarPayload) => {
    setPayload(p);
    setCollapsed(true);
  }, []);

  const expand = useCallback(() => {
    setCollapsed(false);
    setPayload(null);
  }, []);

  const reset = useCallback(() => {
    setCollapsed(false);
    setPayload(null);
  }, []);

  return (
    <DetailBarContext.Provider value={{ collapsed, payload, collapse, expand, reset }}>
      {children}
    </DetailBarContext.Provider>
  );
}
