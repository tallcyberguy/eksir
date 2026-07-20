// Minimal SWR-ish hook to avoid adding a dep right now.
// Pass a key + an async fetcher; returns { data, error, isLoading, mutate }.
"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export default function useSWR<T>(key: string, fetcher: () => Promise<T>) {
  const [data, setData]       = useState<T | undefined>();
  const [error, setError]     = useState<Error | undefined>();
  const [isLoading, setLoad]  = useState(true);
  const mounted = useRef(true);

  const run = useCallback(async () => {
    setLoad(true);
    try {
      const v = await fetcher();
      if (mounted.current) setData(v);
    } catch (e: any) {
      if (mounted.current) setError(e);
    } finally {
      if (mounted.current) setLoad(false);
    }
  }, [key]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    mounted.current = true;
    run();
    return () => { mounted.current = false; };
  }, [run]);

  return { data, error, isLoading, mutate: run };
}
