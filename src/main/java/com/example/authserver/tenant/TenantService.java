package com.example.authserver.tenant;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class TenantService {
    private final TenantRepository repo;

    public TenantService(TenantRepository repo) { this.repo = repo; }

    @Transactional
    public TenantEntity create(String key, String domain, Boolean mfaEnabled, String owner) {
        TenantEntity t = new TenantEntity();
        t.setTenantKey(key);
        t.setDomain(domain);
        t.setIsMfaEnabled(Boolean.TRUE.equals(mfaEnabled));
        t.setOwner(owner);
        return repo.save(t);
    }

    @Transactional
    public TenantEntity update(Long id, String key, String domain, Boolean mfaEnabled, String owner) {
        TenantEntity t = repo.findById(id).orElseThrow();
        if (key != null) t.setTenantKey(key);
        if (domain != null) t.setDomain(domain);
        if (mfaEnabled != null) t.setIsMfaEnabled(mfaEnabled);
        if (owner != null) t.setOwner(owner);
        return repo.save(t);
    }

    public TenantEntity get(Long id) { return repo.findById(id).orElseThrow(); }
    public List<TenantEntity> list() { return repo.findAll(); }

    @Transactional
    public void delete(Long id) { repo.deleteById(id); }
}
