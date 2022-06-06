<?php

namespace App\Http\Controllers;

use App\Mail\otp;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Mail\Mailer;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        //
    }

    /**
     * Show the form for creating a new resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        //
    }

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show($id)
    {
        //
    }

    /**
     * Show the form for editing the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function edit($id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, $id)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function destroy($id)
    {
        //
    }
    public function signUp(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'first_name' => 'required',
            'last_name' => 'required',
            'phone_number' => 'required',
            'email' => 'required|unique:users',
            'type' => 'required',
            'password' => 'required',
            'profile_image' => 'mimes:jpg,jpeg,png'
        ]);

        if ($validator->fails()) {
            return response($validator->messages(), 400);
        }
        $user = new User();
        $user->first_name = $request->first_name;
        $user->last_name = $request->last_name;
        $user->name = $request->first_name . ' ' . $request->last_name;
        $user->phone_number = $request->phone_number;
        $user->email = $request->email;
        $user->password = $request->password;
        $user->type = $request->type;
        $otp = rand(10000, 99999);
        $details = [
            'otp' => $otp,
        ];
        Mail::to($request->email)->send(new otp($details));
        $user->otp = $otp;
        if ($request->hasFile('profile_image')) {
            $file = $request->file('profile_image');
            $sliderImg = 'profile_image_' . Str::random(15) . '.' . $file->getClientOriginalExtension();
            Storage::disk('public_user')->put($sliderImg, \File::get($file));
            $user->profile_image = $sliderImg;
        }
        $user->save();
        return $this->formatResponse('success', 'user sign-up successfully and email send on user account',$otp);
    }
    public function verfiyOtp(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required',
            'password' => 'required',
            'otp' => 'required',
        ]);

        if ($validator->fails()) {
            return response($validator->messages(), 400);
        }
        $user = User::where('email', $request->email)->first();
        if ($user) {
            if ($user->otp == $request->otp) {
                $user->email_verified_at = Carbon::now();
                $user->is_verified = 1;
                $user->save();
                $credentials = $request->only('email', 'password');
                Auth::attempt($credentials);
                $user = Auth::user();
                $user['token'] = auth()->user()->createToken('API Token')->plainTextToken;
                return $this->formatResponse('success', 'user OTP verified', $user);
            }
            return $this->formatResponse('error', 'OTP is not Match', null, 400);
        } else {
            return $this->formatResponse('error', 'Mail is not found', null, 400);
        }
    }
    public function Login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required',
            'password' => 'required',
        ]);

        if ($validator->fails()) {
            return response($validator->messages(), 400);
        }
        $credentials = $request->only('email', 'password');
        if (Auth::attempt($credentials)) {
            $user = Auth::user();
            $user['token'] = auth()->user()->createToken('API Token')->plainTextToken;
            return $this->formatResponse('success', 'user login successfully', $user);
        } else {
            return $this->formatResponse('error', 'Credentials is not Match', null, 401);
        }
    }
    public function forgetPassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required'
        ]);

        if ($validator->fails()) {
            return response($validator->messages(), 400);
        }
        $user = User::where('email', $request->email)->first();
        if ($user) {
            $otp = rand(10000, 99999);
            $details = [
                'otp' => $otp,
            ];
            Mail::to($request->email)->send(new otp($details));
            $user->otp = $otp;
            $user->save();
            return $this->formatResponse('success', 'Reset Password OTP Send on Email');
        } else {
            return $this->formatResponse('error', 'Email is not exist');
        }
    }
    public function verifyForgetPassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required',
            'otp' => 'required'
        ]);
        if ($validator->fails()) {
            return response($validator->messages(), 400);
        }
        $user = User::where('email', $request->email)->first();
        if ($user) {
            if ($user->otp == $request->otp) {
                return $this->formatResponse('success', 'user OTP verified');
            }
            return $this->formatResponse('error', 'OTP is not Match', null, 400);
        } else {
            return $this->formatResponse('error', 'Mail is not found', null, 400);
        }
    }
    public function newPassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required',
            'password' => 'required'
        ]);
        if ($validator->fails()) {
            return response($validator->messages(), 400);
        }
        // update password
        $user = User::where('email',$request->email)->first();
        $user->password = $request->password;
        $user->save();
        $credentials = $request->only('email', 'password');
        if (Auth::attempt($credentials)) {
            $user = Auth::user();
            $user['token'] = auth()->user()->createToken('API Token')->plainTextToken;
            return $this->formatResponse('success', 'user login successfully', $user);
        }
        else{
            return $this->formatResponse('error', 'Some wrong went', null,401);
        }

    }
}
