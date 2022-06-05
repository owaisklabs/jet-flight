<?php

use App\Http\Controllers\AuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Laravel\Jetstream\Rules\Role;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

Route::controller(AuthController::class)->group(function(){
    Route::post('sign-up','signUp');
    Route::post('verify-otp','verfiyOtp');
    Route::post('login','Login');
    Route::post('forget-password','forgetPassword');
    Route::post('verify-forget-password-otp','verifyForgetPassword');
    Route::post('new-password','newPassword');
});
