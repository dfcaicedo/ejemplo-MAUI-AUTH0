using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using logins.Config;
using logins.Models;

namespace logins.Services;

/// <summary>
/// PROVEEDOR 1 — Supabase Auth (GoTrue) hablando directo con su API REST, sin SDK, para que se vea qué viaja.
///
/// Flujo:
///   1. POST /auth/v1/token?grant_type=password  → Supabase valida correo/clave y devuelve un JWT (access_token).
///   2. GET  /rest/v1/user_roles?user_id=eq.{id} → con ese JWT consultamos NUESTRA tabla de roles.
///      Postgres aplica Row Level Security usando el JWT (auth.uid()), así el cliente solo ve lo que le toca.
/// Autenticación (quién eres) = Supabase.  Autorización (qué puedes hacer) = tabla user_roles.
/// </summary>
public sealed class SupabaseAuthService : IRoleDirectory
{
    private static readonly HttpClient Http = new();

    public async Task<UserSession> SignInAsync(string email, string password)
    {
        using var doc = await SendAuthAsync("token?grant_type=password", email, password);
        return await BuildSessionAsync(doc.RootElement)
               ?? throw new InvalidOperationException("Supabase no devolvió una sesión.");
    }

    /// <summary>
    /// CAMINO B — Google ASISTIDO por Supabase. La app NO habla con Google: habla con Supabase.
    ///  1. Abrimos {supabase}/auth/v1/authorize?provider=google (+ PKCE). Supabase redirige a Google
    ///     usando SU client id/secret (configurados en el dashboard de Supabase, no en la app).
    ///  2. Google devuelve el control a Supabase (…/auth/v1/callback); Supabase crea/busca el usuario
    ///     en auth.users y redirige a nuestra app con ?code=...
    ///  3. Canjeamos ese code por la sesión de Supabase (JWT) en /auth/v1/token?grant_type=pkce.
    ///  4. Con el JWT leemos el rol en public.user_roles, igual que en el login por correo.
    /// </summary>
    public async Task<UserSession> SignInWithGoogleAsync(CancellationToken ct = default)
    {
        var pkce = OAuthHelper.NewPkce();
        var mobileRedirect = $"{AuthConfig.SupabaseAndroidRedirectScheme}://callback";

        var redirect = await OAuthHelper.AuthorizeAsync(redirectUri =>
            $"{AuthConfig.SupabaseUrl}/auth/v1/authorize?provider=google"
            + $"&redirect_to={Uri.EscapeDataString(redirectUri)}"
            + $"&code_challenge={pkce.Challenge}&code_challenge_method=s256", mobileRedirect, ct);

        if (string.IsNullOrEmpty(redirect.Code))
            throw new InvalidOperationException("Supabase no devolvió un código (¿la URL de redirección está en la lista permitida?).");

        using var req = new HttpRequestMessage(HttpMethod.Post, $"{AuthConfig.SupabaseUrl}/auth/v1/token?grant_type=pkce")
        {
            Content = JsonContent.Create(new { auth_code = redirect.Code, code_verifier = pkce.Verifier })
        };
        req.Headers.Add("apikey", AuthConfig.SupabaseAnonKey);
        using var res = await Http.SendAsync(req, ct);
        var body = await res.Content.ReadAsStringAsync(ct);
        if (!res.IsSuccessStatusCode)
            throw new InvalidOperationException(ExtractError(body) ?? $"Supabase respondió {(int)res.StatusCode}");

        using var doc = JsonDocument.Parse(body);
        return await BuildSessionAsync(doc.RootElement)
               ?? throw new InvalidOperationException("Supabase no devolvió una sesión.");
    }

    /// <summary>Devuelve la sesión, o null si el proyecto exige confirmar el correo antes de entrar.</summary>
    public async Task<UserSession?> SignUpAsync(string email, string password)
    {
        using var doc = await SendAuthAsync("signup", email, password);
        return await BuildSessionAsync(doc.RootElement);
    }

    private static async Task<JsonDocument> SendAuthAsync(string path, string email, string password)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{AuthConfig.SupabaseUrl}/auth/v1/{path}")
        {
            Content = JsonContent.Create(new { email, password })
        };
        req.Headers.Add("apikey", AuthConfig.SupabaseAnonKey);

        using var res = await Http.SendAsync(req);
        var body = await res.Content.ReadAsStringAsync();
        if (!res.IsSuccessStatusCode)
            throw new InvalidOperationException(ExtractError(body) ?? $"Supabase respondió {(int)res.StatusCode}");
        return JsonDocument.Parse(body);
    }

    private async Task<UserSession?> BuildSessionAsync(JsonElement root)
    {
        if (!root.TryGetProperty("access_token", out var tokenEl)) return null; // signup sin sesión

        var token = tokenEl.GetString()!;
        var user = root.GetProperty("user");
        var id = user.GetProperty("id").GetString()!;
        var email = user.GetProperty("email").GetString() ?? "";
        string? name = user.TryGetProperty("user_metadata", out var meta)
                       && meta.TryGetProperty("full_name", out var fn) ? fn.GetString() : null;

        var role = await GetRoleAsync(id, token);
        return new UserSession(id, email, name, AuthProviderKind.Supabase, role, token);
    }

    // ───── tabla de roles en Postgres (vía PostgREST) ─────

    private static async Task<string> GetRoleAsync(string userId, string token)
    {
        using var req = NewRest(HttpMethod.Get, $"user_roles?select=role&user_id=eq.{userId}", token);
        using var res = await Http.SendAsync(req);
        res.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync());
        // El trigger de schema.sql crea la fila al registrarse; si faltara, asumimos el rol más bajo.
        return doc.RootElement.GetArrayLength() > 0
            ? doc.RootElement[0].GetProperty("role").GetString() ?? Roles.Viewer
            : Roles.Viewer;
    }

    public async Task<IReadOnlyList<RoleEntry>> ListAsync(UserSession s)
    {
        // RLS: un admin ve todas las filas; un usuario normal solo vería la suya.
        using var req = NewRest(HttpMethod.Get, "user_roles?select=user_id,email,role&order=email", s.AccessToken);
        using var res = await Http.SendAsync(req);
        res.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync());
        return doc.RootElement.EnumerateArray()
            .Select(e => new RoleEntry(e.GetProperty("user_id").GetString()!,
                                       e.GetProperty("email").GetString() ?? "",
                                       e.GetProperty("role").GetString()!))
            .ToList();
    }

    public async Task SetRoleAsync(UserSession s, string userKey, string role)
    {
        using var req = NewRest(new HttpMethod("PATCH"), $"user_roles?user_id=eq.{userKey}", s.AccessToken);
        req.Content = JsonContent.Create(new { role });
        using var res = await Http.SendAsync(req);
        if (!res.IsSuccessStatusCode)
            throw new InvalidOperationException($"No se pudo cambiar el rol ({(int)res.StatusCode}). ¿Eres admin?");
    }

    private static HttpRequestMessage NewRest(HttpMethod method, string path, string token)
    {
        var req = new HttpRequestMessage(method, $"{AuthConfig.SupabaseUrl}/rest/v1/{path}");
        req.Headers.Add("apikey", AuthConfig.SupabaseAnonKey);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token); // el JWT del usuario
        return req;
    }

    private static string? ExtractError(string body)
    {
        try
        {
            using var d = JsonDocument.Parse(body);
            foreach (var key in new[] { "msg", "error_description", "message" })
                if (d.RootElement.TryGetProperty(key, out var v)) return v.GetString();
        }
        catch { /* cuerpo no JSON */ }
        return null;
    }
}
