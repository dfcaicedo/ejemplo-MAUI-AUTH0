namespace logins.Models;

public static class Roles
{
    public const string Admin = "admin";
    public const string Editor = "editor";
    public const string Viewer = "viewer";
    public static readonly string[] All = { Admin, Editor, Viewer };
}

public enum AuthProviderKind { Supabase, GoogleDirect }

/// <summary>Usuario autenticado: quién es (lo dice el tercero) + qué puede hacer (lo dice nuestra tabla de roles).</summary>
public sealed record UserSession(
    string UserId,
    string Email,
    string? DisplayName,
    AuthProviderKind Provider,
    string Role,
    string AccessToken);

public sealed record RoleEntry(string UserKey, string Email, string Role);
