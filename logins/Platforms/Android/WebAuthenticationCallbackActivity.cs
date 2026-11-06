using Android.App;
using Android.Content;
using Android.Content.PM;
using logins.Config;

namespace logins;

/// <summary>Recibe la redirección de Google en Android (esquema inverso del client id) y se la pasa a WebAuthenticator.</summary>
[Activity(NoHistory = true, LaunchMode = LaunchMode.SingleTop, Exported = true)]
[IntentFilter(new[] { Intent.ActionView },
    Categories = new[] { Intent.CategoryDefault, Intent.CategoryBrowsable },
    DataScheme = AuthConfig.GoogleAndroidRedirectScheme,
    DataPath = "/oauth2redirect")]
// Retorno desde Supabase (login con Google asistido): com.companyname.logins://callback
[IntentFilter(new[] { Intent.ActionView },
    Categories = new[] { Intent.CategoryDefault, Intent.CategoryBrowsable },
    DataScheme = AuthConfig.SupabaseAndroidRedirectScheme,
    DataHost = "callback")]
public class WebAuthenticationCallbackActivity : Microsoft.Maui.Authentication.WebAuthenticatorCallbackActivity
{
}
