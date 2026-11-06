# Login con terceros + roles (.NET MAUI)

## Los dos caminos que demuestra
- **A · Google nativo:** la app habla directo con Google (OAuth 2.0 + PKCE). Rol en SQLite local. Código: `GoogleAuthService.cs`.
- **B · Asistido por Supabase:** la app habla con Supabase, y Supabase habla con Google y entrega un JWT. Rol en Postgres con RLS. Código: `SupabaseAuthService.SignInWithGoogleAsync` (también hay correo/clave).
- Lo común (PKCE + recepción de la redirección) está en `OAuthHelper.cs`.

**Configuración extra del camino B (en el dashboard de Supabase):**
1. Authentication → URL Configuration → Redirect URLs: agrega `com.companyname.logins://callback` y `http://127.0.0.1:**`.
2. Authentication → Providers → Google: actívalo con un ID de cliente OAuth tipo **Web** de Google Cloud (redirect autorizado: `https://<ref>.supabase.co/auth/v1/callback`) y pega su client id y secret.

Idea central: **autenticación** (¿quién eres?) la resuelve un tercero; **autorización** (¿qué puedes hacer?) la resuelve tu propia tabla de roles.

| | Autentica | Tabla de roles |
|---|---|---|
| 1. Supabase | Supabase Auth (correo/clave → JWT) | `public.user_roles` en Postgres, protegida con RLS |
| 2. Google directo | Google OAuth 2.0 + PKCE | `local_user_roles` en SQLite (local) |

## Archivos clave
- `logins/Services/SupabaseAuthService.cs` – login por REST + lectura de roles con el JWT
- `logins/Services/GoogleAuthService.cs` – flujo PKCE paso a paso (comentado)
- `logins/Services/LocalRoleStore.cs` – tabla de roles local
- `logins/ViewModels/HomeViewModel.cs` – la UI cambia según el rol
- `supabase/schema.sql` – tabla, RLS y trigger
- `logins/Config/AuthConfig.cs` – claves a completar

## Parametrización (Git)
`logins/Config/AuthConfig.cs` tiene los valores reales y está en `.gitignore`. Lo que se sube es la plantilla `logins/Config/AuthConfig.cs.example`.
Tras clonar: copia `AuthConfig.cs.example` → `AuthConfig.cs` y reemplaza los valores `TU-...`. Si falta configurar, la pantalla de login lo avisa.

## Configuración
**Supabase:** ejecuta `supabase/schema.sql` en el SQL Editor, copia URL y anon key a `AuthConfig`. Para pruebas rápidas desactiva *Confirm email* (Authentication → Providers → Email). Hazte admin con el `update` del final del script.

**Google:** Google Cloud Console → Credenciales → *ID de cliente OAuth* tipo **Aplicación de escritorio** (Windows/Mac) y/o **Android** (paquete `com.companyname.logins` + SHA-1). Configura la pantalla de consentimiento y agrega tu correo como usuario de prueba. Copia los valores a `AuthConfig`.

## Ejecutar
`dotnet build -f net10.0-windows10.0.19041.0` o F5 en Visual Studio con "Windows Machine".

La plantilla original de MAUI quedó respaldada en `_plantilla_original/`.
