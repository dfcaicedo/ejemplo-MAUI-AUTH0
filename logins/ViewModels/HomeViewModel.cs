using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using logins.Models;
using logins.Services;

namespace logins.ViewModels;

public partial class HomeViewModel : ObservableObject
{
    private readonly SessionService _session;
    private readonly SupabaseAuthService _supabase;
    private readonly LocalRoleStore _local;

    public HomeViewModel(SessionService session, SupabaseAuthService supabase, LocalRoleStore local)
    {
        _session = session;
        _supabase = supabase;
        _local = local;
    }

    public ObservableCollection<RoleEntry> RoleRows { get; } = new();
    public string[] AvailableRoles => Roles.All;

    [ObservableProperty] private string welcome = "";
    [ObservableProperty] private string providerText = "";
    [ObservableProperty] private string roleText = "";
    [ObservableProperty] private string rolesSource = "";
    [ObservableProperty] private string message = "";
    [ObservableProperty] private bool canEdit;
    [ObservableProperty] private bool isAdmin;

    private IRoleDirectory Directory(UserSession s) =>
        s.Provider == AuthProviderKind.Supabase ? _supabase : _local;

    /// <summary>Se llama cada vez que aparece la página. Aquí es donde el rol decide qué se muestra.</summary>
    public async Task LoadAsync()
    {
        var s = _session.Current;
        if (s is null) { await Shell.Current.GoToAsync("//login"); return; }

        Welcome = $"Hola, {s.DisplayName ?? s.Email}";
        ProviderText = s.Provider == AuthProviderKind.Supabase
            ? "Asistido por Supabase (Supabase Auth)"
            : "Google nativo (OAuth 2.0 + PKCE)";
        RoleText = s.Role;
        RolesSource = s.Provider == AuthProviderKind.Supabase
            ? "Tabla de roles: public.user_roles en Postgres (Supabase, protegida con RLS)"
            : "Tabla de roles: local_user_roles en SQLite (archivo del dispositivo)";

        // Autorización: decisiones según el rol.
        CanEdit = s.Role is Roles.Admin or Roles.Editor;
        IsAdmin = s.Role == Roles.Admin;

        RoleRows.Clear();
        if (IsAdmin) await RefreshRoles(s);
    }

    private async Task RefreshRoles(UserSession s)
    {
        try { foreach (var r in await Directory(s).ListAsync(s)) RoleRows.Add(r); }
        catch (Exception ex) { Message = ex.Message; }
    }

    [RelayCommand]
    private async Task ChangeRole(RoleEntry entry)
    {
        var s = _session.Current!;
        var page = Shell.Current.CurrentPage;
        var newRole = await page.DisplayActionSheetAsync($"Rol para {entry.Email}", "Cancelar", null, Roles.All);
        if (newRole is null || newRole == "Cancelar" || newRole == entry.Role) return;

        try
        {
            await Directory(s).SetRoleAsync(s, entry.UserKey, newRole);
            RoleRows.Clear();
            await RefreshRoles(s);
            Message = $"{entry.Email} ahora es {newRole}.";
        }
        catch (Exception ex) { Message = ex.Message; }
    }

    [RelayCommand]
    private async Task SignOut()
    {
        _session.SignOut();
        await Shell.Current.GoToAsync("//login");
    }
}
