using logins.Models;

namespace logins.Services;

/// <summary>Dónde vive la tabla de roles: en Supabase (Postgres) o en SQLite local.</summary>
public interface IRoleDirectory
{
    Task<IReadOnlyList<RoleEntry>> ListAsync(UserSession session);
    Task SetRoleAsync(UserSession session, string userKey, string role);
}
