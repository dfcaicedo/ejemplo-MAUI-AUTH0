using logins.Pages;
using logins.Services;
using logins.ViewModels;
using Microsoft.Extensions.Logging;

namespace logins;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();
        builder
            .UseMauiApp<App>()
            .ConfigureFonts(fonts =>
            {
                fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
                fonts.AddFont("OpenSans-Semibold.ttf", "OpenSansSemibold");
            });

#if DEBUG
        builder.Logging.AddDebug();
#endif

        // Servicios de autenticación / autorización
        builder.Services.AddSingleton<SessionService>();
        builder.Services.AddSingleton<LocalRoleStore>();      // roles locales (SQLite)
        builder.Services.AddSingleton<SupabaseAuthService>(); // proveedor 1
        builder.Services.AddSingleton<GoogleAuthService>();   // proveedor 2

        builder.Services.AddTransient<LoginViewModel>();
        builder.Services.AddTransient<HomeViewModel>();
        builder.Services.AddTransient<LoginPage>();
        builder.Services.AddTransient<HomePage>();

        return builder.Build();
    }
}
