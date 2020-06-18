<?php
require APPPATH . '/libraries/ImplementJwt.php';

require_once APPPATH . 'libraries/codeigniter-predis/src/Redis.php';

use \Firebase\JWT\JWT;

class Uedu extends CI_Controller
{
    public function __construct()
    {
        parent::__construct();

        $this->objOfJwt = new ImplementJwt();
            $this->redis = new \CI_Predis\Redis();

        header('Content-Type: application/json');

          $this->load->model('tutor_model', 'tutor');
          $this->load->model('regularclass_model', 'regularclass');
          $this->load->library('session');

    }


    /////////// Generating Token and put user data into  token ///////////

    public function LoginToken()
    {
            $tokenData['uniqueId'] = '55555';
            $tokenData['role'] = 'admin';
            $tokenData['timeStamp'] = Date('Y-m-d h:i:s');
            $jwtToken = $this->objOfJwt->GenerateToken($tokenData);
            echo json_encode(array('Token'=>$jwtToken));
         }


         public function zoomToken(){
           $tokenData['iss'] =  'OYfYnfotR7CY75ve-OpVXw';
           $tokenData['exp'] = Date('Y-m-d h:i:s');

           $jwtToken = $this->objOfJwt->GenerateToken($tokenData);

           echo json_encode($jwtToken);

         }


         public function getAuthRole(){



   $received_Token = $this->input->request_headers('Authorization');



         echo json_encode($received_Token);



         }


         public function getToken(){


           $received_Token = $this->input->request_headers('Authorization');


           $token = str_replace("Bearer", "", $received_Token['Authorization']);

           $token = str_replace(" ", "", $token);




           try
               {
               $jwtData = $this->objOfJwt->DecodeToken($token);

               return $jwtData;
               }
               catch (Exception $e)
               {
               http_response_code('401');
               echo json_encode(array( "status" => false, "message" => $e->getMessage()));exit;
               }



         }





         public function signIn(){



           $config = array(


array(
'field' => 'id',
'label' => 'Id',
'rules' => 'trim|required'

),

array(
'field' => 'pw',
'label' => 'Password',
'rules' => 'trim|required'

)

           );



           $this->form_validation->set_rules($config);

           if($this->form_validation->run() === FALSE){

             $result['error'] = true;
             $result['msg'] = array(

             'id' => form_error('id'),
             'pw' => form_error('pw')

           );

           }

           else{

             $data = array(
               'id' => $this->input->post('id'),
               'pw' => $this->input->post('pw')


             );

            $result  = $this->tutor->signIn($data);
            $result2 = $this->regularclass->signIn($data);

            if($result === false && $result2 === false){



                           $result['error'] = true;
                           $result['msg'] = 'Credentials failed';
            }

            else{

              if($result2){

                $result = $result2;
              }

              $jwtToken = $this->objOfJwt->GenerateToken($result);

               $user = $this->objOfJwt->DecodeToken($jwtToken)[0];


                if($user && $jwtToken){



                           echo json_encode( array('token'=> $jwtToken, 'user' => $user));



                                     $this->redis->publish('notif', json_encode($user));



                           return;

              }
            }




           }

           echo json_encode($result);

     }

    //////// get data from token ////////////

    public function GetTokenData()
    {
    $received_Token = $this->input->request_headers('Authorization');
        try
            {
            $jwtData = $this->objOfJwt->DecodeToken($received_Token['token']);
            echo json_encode($jwtData);
            }
            catch (Exception $e)
            {
            http_response_code('401');
            echo json_encode(array( "status" => false, "message" => $e->getMessage()));exit;
            }
    }


    public function create_tutor_meeting(){



      $this->load->library('codeigniter-guzzle/guzzle');
      $client = new GuzzleHttp\Client(['base_uri' => 'https://api.zoom.us']);

      $key = "w0XvAh4gzAsaQWqPi0dURDloRqn55iAGP0Dk";
      $payload = array(
          "iss" => "OYfYnfotR7CY75ve-OpVXw",
          "exp" => time()+36000, // expire in 10 hours
      );

      $jwt = JWT::encode($payload, $key, 'HS256'); // use the secret to sign the payload with a specific hashing algorithim



         try {
             $response = $client->request('POST', '/v2/users/me/meetings', [
                 "headers" => [
                     "Authorization" => "Bearer $jwt"
                 ],
                 'json' => [
                     "topic" => "test",
                     "type" => 2,
                     "start_time" => "2020-06-16T20:30:00",
                     "duration" => "30", // 30 mins
                     "password" => "123456"
                 ],
             ]);

             $data = json_decode($response->getBody());
             echo "Join URL: ". $data->join_url;
             echo "<br>";
             echo "Meeting Password: ". $data->password;

         } catch(Exception $e) {

                 echo $e->getMessage();
             }







}


function generate_signature ( $api_key, $api_sercet, $meeting_number, $role){

	$time = time() * 1000; //time in milliseconds (or close enough)

	$data = base64_encode($api_key . $meeting_number . $time . $role);

	$hash = hash_hmac('sha256', $data, $api_sercet, true);

	$_sig = $api_key . "." . $meeting_number . "." . $time . "." . $role . "." . base64_encode($hash);

	//return signature, url safe base64 encoded
	return rtrim(strtr(base64_encode($_sig), '+/', '-_'), '=');
}
public function generate_student_signature(){




  $classId = $this->input->post('classData');
  $tutorConn = $this->input->post('tutorData');

  $meetingId = '';
  $meetingPw = '';
  $userName = '';


  if($classId && $tutorConn){

      $tutor = $this->tutor->get_tutor_by_conn($tutorConn) ? $this->tutor->get_tutor_by_conn($tutorConn)[0] : '';

      if($tutor){

        $schedules = json_decode($tutor->class_schedule);

      if($schedules){


        foreach ($schedules as $key => $value) {


        if($value->schedule->classid === $classId && $value->active === true){

            $meetingId  = property_exists($value->schedule, 'meetingId') ? $value->schedule->meetingId : '';
            $meetingPw  = property_exists($value->schedule, 'meetingPw') ? $value->schedule->meetingPw : '';
            $userName = $value->schedule->name;
        }
        }


        if($meetingId && $meetingPw) {



          $key = "OYfYnfotR7CY75ve-OpVXw";

          $payload = array(
              "meetingNumber" => (int)$meetingId,
              "apiKey" => "OYfYnfotR7CY75ve-OpVXw",
              'apiSecret' => "w0XvAh4gzAsaQWqPi0dURDloRqn55iAGP0Dk",
              'role' => (int)0
);
          $jwt = $this->generate_signature("OYfYnfotR7CY75ve-OpVXw", "w0XvAh4gzAsaQWqPi0dURDloRqn55iAGP0Dk", (int)$meetingId, (int)0);


          $roomData = array(

            "meetingNumber" => (int)$meetingId,
            "signature" => $jwt,
            'apiKey' =>  "OYfYnfotR7CY75ve-OpVXw",
            'password' => (int)$meetingPw,
            'userName' => $userName
          );

  echo json_encode($roomData);
        }


}
      }
}


}

}
