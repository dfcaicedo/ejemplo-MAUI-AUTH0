using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using logins.Services;

namespace logins.ViewModels;

public partial class LoginViewModel : ObservableObject
{
    private readonly SupabaseAuthService _supabase;
    private readonly GoogleAuthService _google;
    private readonly SessionService _session;

    public LoginViewModel(SupabaseAuthService supabase, GoogleAuthService google, SessionService session)
    {
        _supabase = supabase;
        _google = google;
        _session = session;
    }

    [ObservableProperty] private string email = "";
    [ObservableProperty] private string password = "";
    [ObservableProperty] private string message = "";
    [ObservableProperty, NotifyPropertyChangedFor(nameof(IsNotBusy))] private bool isBusy;
    public bool IsNotBusy => !IsBusy;

    private const string SupabaseMissing = "Supabase no está configurado: completa SupabaseUrl y SupabaseAnonKey en Config/AuthConfig.cs.";
    private const string GoogleMissing = "Google no está configurado: completa los client id en Config/AuthConfig.cs.";

    [RelayCommand] private Task SupabaseSignIn() => Run(async () =>
    {
        var s = await _supabase.SignInAsync(Email.Trim(), Password);
        await Complete(s);
    }, Config.AuthConfig.SupabaseConfigured, SupabaseMissing);

    [RelayCommand] private Task SupabaseSignUp() => Run(async () =>
    {
        var s = await _supabase.SignUpAsync(Email.Trim(), Password);
        if (s is null) Message = "Cuenta creada. Confirma tu correo y luego inicia sesión.";
        else await Complete(s);
    }, Config.AuthConfig.SupabaseConfigured, SupabaseMissing);

    [RelayCommand] private Task SupabaseGoogleSignIn() => Run(async () =>
    {
        var s = await _supabase.SignInWithGoogleAsync();
        await Complete(s);
    }, Config.AuthConfig.SupabaseConfigured, SupabaseMissing);

    [RelayCommand] private Task GoogleSignIn() => Run(async () =>
    {
        var s = await _google.SignInAsync();
        await Complete(s);
    }, Config.AuthConfig.GoogleConfigured, GoogleMissing);

    private async Task Complete(Models.UserSession s)
    {
        _session.SignIn(s);
        Password = "";
        await Shell.Current.GoToAsync("//home");
    }

    private async Task Run(Func<Task> action, bool configured, string notConfiguredMessage)
    {
        if (!configured) { Message = notConfiguredMessage; return; }
        IsBusy = true;
        Message = "";
        try { await action(); }
        catch (OperationCanceledException) { Message = "Cancelado."; }
        catch (Exception ex) { Message = ex.Message; }
        finally { IsBusy = false; }
    }
}
