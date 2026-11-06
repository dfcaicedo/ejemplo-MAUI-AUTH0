using logins.Models;

namespace logins.Services;

/// <summary>Guarda en memoria quién está logueado. Solo para el ejemplo (sin persistir tokens).</summary>
public sealed class SessionService
{
    public UserSession? Current { get; private set; }
    public void SignIn(UserSession s) => Current = s;
    public void SignOut() => Current = null;
}
