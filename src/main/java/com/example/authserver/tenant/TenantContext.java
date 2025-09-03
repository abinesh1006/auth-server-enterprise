package com.example.authserver.tenant;
public class TenantContext {
    private static final ThreadLocal<TenantInfo> CURRENT = new ThreadLocal<>();
    public static void set(TenantInfo info) { CURRENT.set(info); }
    public static TenantInfo get() { return CURRENT.get(); }
    public static void clear() { CURRENT.remove(); }
    public record TenantInfo(Long id, String key, String domain, boolean mfaEnabled) {}
}
