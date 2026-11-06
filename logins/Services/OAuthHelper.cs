using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace logins.Services;

/// <summary>
/// Piezas comunes de cualquier flujo "Authorization Code + PKCE" en una app nativa:
/// generar el par verifier/challenge y recibir la redirección con el code.
/// Las usan tanto el login nativo con Google como el login con Google asistido por Supabase.
/// </summary>
public static class OAuthHelper
{
    public sealed record Pkce(string Verifier, string Challenge, string State);
    public sealed record RedirectResult(string? Code, string? State, string RedirectUri);

    /// <summary>Verifier aleatorio, challenge = BASE64URL(SHA256(verifier)) y un state anti-CSRF.</summary>
    public static Pkce NewPkce()
    {
        var verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        var challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        return new Pkce(verifier, challenge, Base64Url(RandomNumberGenerator.GetBytes(16)));
    }

    public static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>
    /// Abre el navegador del sistema en la URL de autorización y espera la redirección.
    ///   · Android:      esquema propio (mobileRedirectUri) recibido por WebAuthenticator.
    ///   · Windows/Mac:  servidor loopback temporal en http://127.0.0.1:{puerto}/.
    /// buildAuthUrl recibe el redirect_uri a usar y devuelve la URL completa de autorización.
    /// </summary>
    public static async Task<RedirectResult> AuthorizeAsync(
        Func<string, string> buildAuthUrl, string mobileRedirectUri, CancellationToken ct = default)
    {
#if ANDROID
        var authUrl = buildAuthUrl(mobileRedirectUri);
        var result = await WebAuthenticator.Default.AuthenticateAsync(new Uri(authUrl), new Uri(mobileRedirectUri));
        result.Properties.TryGetValue("code", out var code);
        result.Properties.TryGetValue("state", out var state);
        return new RedirectResult(code, state, mobileRedirectUri);
#else
        var port = GetFreePort();
        var redirectUri = $"http://127.0.0.1:{port}/";

        using var listener = new HttpListener();
        listener.Prefixes.Add(redirectUri);
        listener.Start();

        await Launcher.Default.OpenAsync(new Uri(buildAuthUrl(redirectUri))); // navegador del sistema

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromMinutes(2));
        var ctxTask = listener.GetContextAsync();
        var finished = await Task.WhenAny(ctxTask, Task.Delay(Timeout.Infinite, timeout.Token));
        if (finished != ctxTask) throw new TimeoutException("Se agotó el tiempo esperando el inicio de sesión.");

        var ctx = await ctxTask;
        var query = ctx.Request.QueryString;
        var html = Encoding.UTF8.GetBytes(
            "<html><body style='font-family:sans-serif;text-align:center;margin-top:15%'>" +
            "<h2>Listo, ya puedes volver a la aplicación.</h2></body></html>");
        ctx.Response.ContentType = "text/html; charset=utf-8";
        await ctx.Response.OutputStream.WriteAsync(html, ct);
        ctx.Response.Close();

        var err = query["error_description"] ?? query["error"];
        if (err is not null) throw new InvalidOperationException($"El proveedor devolvió un error: {err}");
        return new RedirectResult(query["code"], query["state"], redirectUri);
#endif
    }

#if !ANDROID
    private static int GetFreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }
#endif
}
