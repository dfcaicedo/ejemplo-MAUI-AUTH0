using Microsoft.Data.Sqlite;
using logins.Config;
using logins.Models;

namespace logins.Services;

/// <summary>
/// Tabla de roles LOCAL (SQLite) para el login con Google directo.
/// Google solo dice "este es dana@gmail.com y está verificado"; no sabe nada de tus roles.
/// Por eso la autorización vive en tu propia base: aquí, un archivo SQLite en el dispositivo.
/// </summary>
public sealed class LocalRoleStore : IRoleDirectory
{
    private readonly string _connectionString;

    public LocalRoleStore()
    {
        SQLitePCL.Batteries_V2.Init();
        var path = Path.Combine(FileSystem.AppDataDirectory, "roles.db");
        _connectionString = $"Data Source={path}";

        using var cn = Open();
        using var cmd = cn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS local_user_roles (
                email      TEXT PRIMARY KEY,
                role       TEXT NOT NULL CHECK (role IN ('admin','editor','viewer')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """;
        cmd.ExecuteNonQuery();
    }

    private SqliteConnection Open()
    {
        var cn = new SqliteConnection(_connectionString);
        cn.Open();
        return cn;
    }

    /// <summary>Primer login: se crea la fila (admin si el correo está en la lista, si no viewer).</summary>
    public Task<string> GetOrCreateRoleAsync(string email) => Task.Run(() =>
    {
        email = email.ToLowerInvariant();
        using var cn = Open();

        using (var sel = cn.CreateCommand())
        {
            sel.CommandText = "SELECT role FROM local_user_roles WHERE email = $e";
            sel.Parameters.AddWithValue("$e", email);
            if (sel.ExecuteScalar() is string existing) return existing;
        }

        var role = AuthConfig.LocalAdminEmails.Contains(email, StringComparer.OrdinalIgnoreCase)
            ? Roles.Admin : Roles.Viewer;
        using var ins = cn.CreateCommand();
        ins.CommandText = "INSERT INTO local_user_roles (email, role) VALUES ($e, $r)";
        ins.Parameters.AddWithValue("$e", email);
        ins.Parameters.AddWithValue("$r", role);
        ins.ExecuteNonQuery();
        return role;
    });

    public Task<IReadOnlyList<RoleEntry>> ListAsync(UserSession session) => Task.Run<IReadOnlyList<RoleEntry>>(() =>
    {
        using var cn = Open();
        using var cmd = cn.CreateCommand();
        cmd.CommandText = "SELECT email, role FROM local_user_roles ORDER BY email";
        using var r = cmd.ExecuteReader();
        var list = new List<RoleEntry>();
        while (r.Read()) list.Add(new RoleEntry(r.GetString(0), r.GetString(0), r.GetString(1)));
        return list;
    });

    public Task SetRoleAsync(UserSession session, string userKey, string role) => Task.Run(() =>
    {
        // En la base local la protección es de código: solo un admin puede cambiar roles.
        // (En Supabase lo hace RLS en el servidor; aquí no hay servidor, así que lo exigimos nosotros.)
        if (session.Role != Roles.Admin) throw new UnauthorizedAccessException("Solo un admin puede cambiar roles.");

        using var cn = Open();
        using var cmd = cn.CreateCommand();
        cmd.CommandText = "UPDATE local_user_roles SET role = $r WHERE email = $e";
        cmd.Parameters.AddWithValue("$r", role);
        cmd.Parameters.AddWithValue("$e", userKey);
        cmd.ExecuteNonQuery();
    });
}
