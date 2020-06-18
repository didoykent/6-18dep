<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Role extends CI_Controller {

	function __construct(){

    parent::__construct();
		$this->load->model('jwt_model', 'jwt');
    $this->load->model('Qa_model', 'qa');

}


public function getRole(){

if($this->jwt->getToken()){

$user = $this->jwt->getToken()[0];


  echo json_encode($user);
}

}





}
