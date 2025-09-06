package com.example.authserver.tenant;

public class TenantContext {
    private static final ThreadLocal<TenantInfo> context = new ThreadLocal<>();
    public static void set(TenantInfo tenant) { context.set(tenant); }
    public static TenantInfo get() { return context.get(); }
    public static void clear() { context.remove(); }
    public record TenantInfo(Long id, String key, String domain) {}
}