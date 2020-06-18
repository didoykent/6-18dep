
<?php
require APPPATH . '/libraries/ImplementJwt.php';
class Jwt_model extends CI_Model{


  public function __construct()
  {
      parent::__construct();
      $this->objOfJwt = new ImplementJwt();
      header('Content-Type: application/json');


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



}
