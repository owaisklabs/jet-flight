<?php

namespace App\Http\Controllers;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Routing\Controller as BaseController;

class Controller extends BaseController
{
    use AuthorizesRequests, DispatchesJobs, ValidatesRequests;
    public function formatResponse($status,$message,$data=[],$code=400)
    {
        return (
            [
                'status'=>$status,
                'message'=>$message,
                'data'=>$data,
                'code'=>$code
            ]
            );
    }
}
