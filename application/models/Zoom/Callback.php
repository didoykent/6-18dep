<?php
require APPPATH  . '/models/Zoom/Config.php';
class Callback extends CI_Model{




public function __construct(){


try {
  $config = new Config();
  $this->load->library('codeigniter-guzzle/guzzle');

    $client = new GuzzleHttp\Client(['base_uri' => 'https://zoom.us']);

    $response = $client->request('POST', '/oauth/token', [
        "headers" => [
            "Authorization" => "Basic ". base64_encode($config->GET_CLIENT_ID().':'.$config->GET_CLIENT_SECRET())
        ],
        'form_params' => [
            "grant_type" => "authorization_code",
            "redirect_uri" => $config->GET_REDIRECT_URI()
        ],
    ]);

    $token = json_decode($response->getBody()->getContents(), true);



    if( $oldToken = $this->get_access_token()) {

      $this->db->where('id', $oldToken[0]->id);
     $this->db->update('token', $token);

    }
    else{

 $this->db->insert('token', $token);
    }
} catch(Exception $e) {
    echo $e->getMessage();
}


}
public function get_access_token(){
  $query = $this->db->get('token');

  if($query->num_rows() > 0){

    return $query->result();
  }

  else{

    return false;
  }

}


}
