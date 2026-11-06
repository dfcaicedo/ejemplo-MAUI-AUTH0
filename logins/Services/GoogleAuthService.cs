using System.Net.Http.Headers;
using System.Text.Json;
using logins.Config;
using logins.Models;

namespace logins.Services;

/// <summary>
/// CAMINO A — Google NATIVO: la app habla directo con Google (OAuth 2.0 Authorization Code + PKCE, RFC 7636).
/// No hay servidor tuyo ni Supabase en medio.
///
///  1. Generamos code_verifier / code_challenge (OAuthHelper.NewPkce).
///  2. Abrimos el navegador del sistema en accounts.google.com (la app NUNCA ve la clave de Google).
///  3. Google redirige a la app con ?code=...  (loopback en Windows, esquema propio en Android).
///  4. Cambiamos code + code_verifier por tokens en oauth2.googleapis.com/token.
///  5. Con el access_token pedimos el perfil (email, nombre) a /userinfo.
///  6. El ROL lo busca LocalRoleStore: Google no sabe de roles.
/// </summary>
public sealed class GoogleAuthService
{
    private static readonly HttpClient Http = new();
    private readonly LocalRoleStore _roles;

    public GoogleAuthService(LocalRoleStore roles) => _roles = roles;

    public async Task<UserSession> SignInAsync(CancellationToken ct = default)
    {
        var pkce = OAuthHelper.NewPkce();

#if ANDROID
        var clientId = AuthConfig.GoogleAndroidClientId;
        string? secret = null; // los clientes Android no usan secret
        var mobileRedirect = $"{AuthConfig.GoogleAndroidRedirectScheme}:/oauth2redirect";
#else
        var clientId = AuthConfig.GoogleClientId;
        string? secret = AuthConfig.GoogleClientSecret;
        var mobileRedirect = "";
#endif

        var redirect = await OAuthHelper.AuthorizeAsync(redirectUri =>
            "https://accounts.google.com/o/oauth2/v2/auth"
            + $"?client_id={Uri.EscapeDataString(clientId)}"
            + $"&redirect_uri={Uri.EscapeDataString(redirectUri)}"
            + "&response_type=code"
            + $"&scope={Uri.EscapeDataString("openid email profile")}"
            + $"&code_challenge={pkce.Challenge}&code_challenge_method=S256"
            + $"&state={pkce.State}", mobileRedirect, ct);

        if (redirect.State != pkce.State) throw new InvalidOperationException("El 'state' no coincide (posible CSRF).");
        if (string.IsNullOrEmpty(redirect.Code)) throw new InvalidOperationException("Google no devolvió un código.");

        var accessToken = await ExchangeCodeAsync(redirect.Code, pkce.Verifier, clientId, secret, redirect.RedirectUri, ct);
        var (sub, email, name) = await GetProfileAsync(accessToken, ct);

        var role = await _roles.GetOrCreateRoleAsync(email);
        return new UserSession(sub, email, name, AuthProviderKind.GoogleDirect, role, accessToken);
    }

    private static async Task<string> ExchangeCodeAsync(string code, string verifier, string clientId,
        string? secret, string redirectUri, CancellationToken ct)
    {
        var form = new Dictionary<string, string>
        {
            ["code"] = code,
            ["client_id"] = clientId,
            ["redirect_uri"] = redirectUri,
            ["grant_type"] = "authorization_code",
            ["code_verifier"] = verifier,
        };
        if (!string.IsNullOrEmpty(secret)) form["client_secret"] = secret;

        using var res = await Http.PostAsync("https://oauth2.googleapis.com/token", new FormUrlEncodedContent(form), ct);
        var body = await res.Content.ReadAsStringAsync(ct);
        if (!res.IsSuccessStatusCode) throw new InvalidOperationException($"Google rechazó el código: {body}");
        using var doc = JsonDocument.Parse(body);
        return doc.RootElement.GetProperty("access_token").GetString()!;
    }

    private static async Task<(string sub, string email, string? name)> GetProfileAsync(string token, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, "https://openidconnect.googleapis.com/v1/userinfo");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var res = await Http.SendAsync(req, ct);
        res.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
        var r = doc.RootElement;
        return (r.GetProperty("sub").GetString()!,
                r.GetProperty("email").GetString()!,
                r.TryGetProperty("name", out var n) ? n.GetString() : null);
    }
}
