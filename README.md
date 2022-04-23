<p align="center"><a href="https://laravel.com" target="_blank"><img src="https://raw.githubusercontent.com/laravel/art/master/logo-lockup/5%20SVG/2%20CMYK/1%20Full%20Color/laravel-logolockup-cmyk-red.svg" width="400"></a></p>


## Laravel api con jwt laravel v.8

Proyecto de api web con laravel 8 con JWT

- [Laravel v.8](https://laravel.com/docs/8.x).
- [JWT tymon/jwt-auth](https://jwt-auth.readthedocs.io/en/develop/).



### Instalacion de tymon/jwt-auth


Instalar via composer
~~~
composer require tymon/jwt-auth
~~~
Agregar provider en "config/app.php"
~~~
'providers' => [
...
Tymon\JWTAuth\Providers\LaravelServiceProvider::class,
]
~~~
Publicar la configuración
Ejecute el siguiente comando para publicar el archivo de configuración del paquete:
~~~
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
~~~
Ahora debería tener un config/jwt.phparchivo que le permita configurar los conceptos básicos de este paquete.

Generar clave secreta
~~~
php artisan jwt:secret
~~~
Esto actualizará su archivo .env con algo como "JWT_SECRET=foobar"
Es la clave que se utilizará para firmar sus tokens. Cómo suceda eso exactamente dependerá del algoritmo que elija usar.

Actualice su modelo de usuario
En primer lugar, debe implementar el Tymon\JWTAuth\Contracts\JWTSubjectcontrato en su modelo de Usuario, lo que requiere que implemente los 2 métodos getJWTIdentifier()y getJWTCustomClaims().
~~~
<?php

namespace App;

use Tymon\JWTAuth\Contracts\JWTSubject;
use Illuminate\Notifications\Notifiable;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable implements JWTSubject
{
    use Notifiable;
    // Rest omitted for brevity
    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return mixed
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }
    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims()
    {
        return [];
    }
}
~~~

Configurar la protección de autenticación
Dentro de "config/auth.php" , deberá realizar algunos cambios para configurar Laravel para usar la jwt .
~~~
'defaults' => [
    'guard' => 'api',
    'passwords' => 'users',
],
'guards' => [
    'api' => [
        'driver' => 'jwt',
        'provider' => 'users',
    ],
],
~~~

Agregue algunas rutas de autenticación básicas en "routes/api.php" 
~~~
use App\Http\Controllers\AuthController;
Route::group([
    'middleware' => 'api',
    'prefix' => 'auth'
], function ($router) {
    Route::post('login',    [AuthController::class, 'login']);
    Route::post('logout',   [AuthController::class, 'logout']);
    Route::post('refresh',  [AuthController::class, 'refresh']);
    Route::post('me',       [AuthController::class, 'me']);
    Route::post('register', [AuthController::class, 'register']);
});
~~~

Crear el AuthController
~~~
<?php
namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login']]);
    }
    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login()
    {
        $credentials = request(['email', 'password']);

        if (! $token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }
    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());
    }
    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }
    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }
    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }
}
~~~