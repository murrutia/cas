<?php namespace Subfission\Cas\Middleware;

use Closure;
use \App\User;
use Illuminate\Contracts\Auth\Guard;

class CASAuth
{

    protected $auth;
    protected $cas;

    public $password = 'created-from-cas';

    public function __construct(Guard $auth)
    {
        $this->auth = $auth;
        $this->cas = app('cas');
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request $request
     * @param  \Closure $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        if( $this->cas->checkAuthentication() )
        {
            // Store the user credentials in a Laravel managed session
            session()->put('cas_user', $this->cas->user());

            if (config('cas.cas_associate_user')) {
                $user = $this->create_user();
                \Auth::loginUsingId($user->id);
            }

        } else {
            if ($request->ajax() || $request->wantsJson()) {
                return response('Unauthorized.', 401);
            }
            $this->cas->authenticate();
        }

        return $next($request);
    }

    protected function create_user()
    {
        if (! $this->cas->user()) return null;

        $email = $this->cas->user() .'@'. config('cas.cas_email_extension');

        if (! $user = User::where('email', '=', $email)->first()) {
            $user = User::create([
                'name' => $this->cas->user(),
                'password' => $this->password,
                'email' => $email
            ]);
        }

        return $user;
    }
}
